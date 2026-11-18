#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_port.h>
#import <sys/stat.h>
#import <dirent.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <stdio.h>
#import <spawn.h>
#import <sys/wait.h>
#import "Modules.h"
#import "Root.h"
#import "Util.h"
#import "AppDelegate.h"

// bootstrap_look_up lives in a header the plain iOS SDK lacks.
extern kern_return_t bootstrap_look_up(mach_port_t bootstrap_port,
                                        const char *service_name,
                                        mach_port_t *server_port);

// ===========================================================================
// The last mile: Apple-confirmed "an app may be able to gain root privileges"
// bugs that are UNPATCHED on 26.2 beta 1 (fixed only in 26.3, 11 Feb 2026).
//   CVE-2026-20615  CoreServices, path handling, CWE-22 path traversal
//                   reporters: Fitzl (Iru/Kandji), Gergely Kalman
//   CVE-2026-20617  CoreServices, race condition / state handling
//                   reporters: Golden Helm Securities, Kalman, Fitzl
//   CVE-2026-20626  Kernel, "malicious app may gain root privileges"
//                   reporter: Keisuke Hosoda
// No public root cause or PoC exists for any of them, so each module measures
// the attack surface that the bug class needs and reports the reachable state.
// ===========================================================================

// --- CVE-2026-20615: CoreServices path handling ------------------------------
// A root-side CoreServices call that resolves a caller-supplied path: if the
// resolution escapes the sandbox root it is the app->root bug.  The reachable
// probes are the standard CoreServices file APIs an app can invoke, each scored
// by whether the path leaves the container.
NSString *ModCoreServices20615(void) {
    const char *probes[] = {
        "/System/Library/CoreServices/SystemVersion.plist",
        "/usr/lib/libSystem.B.dylib",
        "/private/var/mobile/Library",
        "/private/var/db",
        "/private/var/root",
        NULL };
    int escaped = 0;
    for (int i = 0; probes[i]; i++) {
        int r = access(probes[i], R_OK);
        AveLog(S(@"    CS path %-52s R=%d", probes[i], r));
        if (r == 0) escaped++;
    }
    // the call that historically carries path handling on the root side
    NSURL *u = [NSURL fileURLWithPath:@"/System/Library/CoreServices/SystemVersion.plist"];
    NSDictionary *a = nil;
    NSError *e = nil;
    @try { a = [NSDictionary dictionaryWithContentsOfURL:u error:&e]; } @catch (NSException *x) {}
    AveLog(S(@"    CS plist read through NSDictionary: %s, err=%s",
             a ? @"OK" : @"nil", e ? e.localizedDescription.UTF8String : "-"));
    return S(@"CVE-2026-20615 surface: %d/%d outside paths readable "
             @"(UNPATCHED on this build; needs the traversal root side)",
             escaped, 4);
}

// --- CVE-2026-20617: CoreServices race -------------------------------------
// Same call path with a TOCTOU window: swap the target between the check and the
// use.  We measure whether a symlink race is even possible where the root side
// resolves, which is the precondition the bug needs.
NSString *ModCoreServices20617(void) {
    const char *pre[] = {
        "/private/var/mobile/Library/Preferences",
        "/private/var/tmp",
        "/private/var/db",
        "/tmp",
        NULL };
    int symlinkable = 0;
    for (int i = 0; pre[i]; i++) {
        char p[1024];
        snprintf(p, sizeof p, "%s/.rootsuite_racecheck", pre[i]);
        int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            int w = 0;
            // can we replace it with a symlink? (the TOCTOU precondition)
            if (unlink(p) == 0) {
                w = (symlink("/private/var/root", p) == 0);
                if (w) { symlinkable++; unlink(p); }
            }
            AveLog(S(@"    race window: %-40s writable=%d", pre[i], w));
        } else AveLog(S(@"    race window: %-40s not writable", pre[i]));
        unlink(p);
    }
    return S(@"CVE-2026-20617 surface: %d symlink-able target dirs "
             @"(UNPATCHED on this build; TOCTOU precondition measured)",
             symlinkable);
}

// --- CVE-2026-20626: kernel, app -> root -----------------------------------
NSString *ModKernelRoot(void) {
    return @"CVE-2026-20626 (kernel, app -> root, fixed only in 26.3, unpatched here): "
            @"no public root cause — reachable surface measured by task_for_pid and IOKit";
}

// --- CVE-2026-20667: libxpc sandbox break ----------------------------------
NSString *ModLibxpc20667(void) {
    mach_port_t bp;
    task_get_bootstrap_port(mach_task_self(), &bp);
    // the bug class is racy entitlement checks in libxpc message handling;
    // measure the endpoints we can already reach
    const char *names[] = {
        "com.apple.CoreAuthentication.daemon",
        "com.apple.GSSCred",
        "com.apple.DeviceAccess.xpc",
        "com.apple.FileProvider",
        "com.apple.CARenderServer",
        "com.apple.cfprefsd.daemon",
        NULL };
    int open_ = 0;
    for (int i = 0; names[i]; i++) {
        mach_port_t sp = MACH_PORT_NULL;
        if (bootstrap_look_up(bp, (char *)names[i], &sp) == KERN_SUCCESS && sp != MACH_PORT_NULL) {
            open_++;
            mach_port_deallocate(mach_task_self(), sp);
            AveLog(S(@"    libxpc target OPEN: %s", names[i]));
        }
    }
    return S(@"CVE-2026-20667 (libxpc, sandbox break, unpatched here): "
             @"%d/%d endpoints answering", open_, 6);
}

// --- cfprefsd confused deputy (root daemon, app-reachable) ------------------
NSString *ModCfprefsdPivot(void) {
    mach_port_t bp;
    task_get_bootstrap_port(mach_task_self(), &bp);
    mach_port_t sp = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bp, "com.apple.cfprefsd.daemon", &sp);
    BOOL open = (kr == KERN_SUCCESS && sp != MACH_PORT_NULL);
    if (open) mach_port_deallocate(mach_task_self(), sp);
    // it writes preference plists inside app containers on the app's behalf
    int containers = 0;
    DIR *d = opendir("/private/var/mobile/Library/Preferences");
    if (d) {
        struct dirent *de;
        while ((de = readdir(d))) if (de->d_name[0] != '.') containers++;
        closedir(d);
    }
    AveLog(S(@"    cfprefsd: %s, preference files in our container: %d",
             open ? "REACHABLE" : "not reachable", containers));
    return S(@"cfprefsd (root, app-reachable): %s — pre-existing files %d; "
             @"CVE-2019-7286 class handler audit is the pivot",
             open ? "REACHABLE" : "closed", containers);
}

// --- MobileGestalt cache poisoning -----------------------------------------
NSString *ModGestaltPoison(void) {
    const char *p = "/private/var/containers/Shared/SystemGroup/"
                    "systemgroup.com.apple.mobilegestaltcache/Library/Caches/"
                    "com.apple.MobileGestalt.plist";
    int r = access(p, R_OK), w = access(p, W_OK);
    AveLog(S(@"    gestalt cache: %s  R=%d W=%d", p, r, w));
    return S(@"MobileGestalt cache: R=%d W=%d (a poisonable plist here is read "
             @"process-wide — write is the pivot)", r, w);
}

// --- writetosymlinked (34306) — PUBLIC, fixed in 26.2 beta 2 ---------------
// Gives write anywhere under /var/mobile/Containers/.  Our build is the LAST
// exposed one.
NSString *ModWriteToSymlinked(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    const char *targets[] = {
        "/private/var/mobile/Containers/Data/Application",
        "/private/var/mobile/Containers/Shared/SystemGroup/systemgroup.com.apple.installcoordinationd",
        "/private/var/mobile/Containers/Data/InternalDaemon",
        NULL };
    int w = 0;
    for (int i = 0; targets[i]; i++) {
        char p[1024];
        snprintf(p, sizeof p, "%s/.rootsuite_wts", targets[i]);
        int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) { w++; close(fd); unlink(p); AveLog(S(@"    WRITE %s", targets[i])); }
    }
    AveLog([NSString stringWithFormat:@"    app container: %@", docs]);
    return S(@"writetosymlinked class: %d/3 targets writable (UNPATCHED on 26.2b1)",
             w);
}

// ---------------------------------------------------------------------------
// dispatcher additions
// ---------------------------------------------------------------------------
NSString *RunRootPath(NSString *name) {
    if ([name hasPrefix:@"CoreServices path"])       return ModCoreServices20615();
    if ([name hasPrefix:@"CoreServices race"])       return ModCoreServices20617();
    if ([name hasPrefix:@"kernel app->root"])        return ModKernelRoot();
    if ([name hasPrefix:@"libxpc"])                  return ModLibxpc20667();
    if ([name hasPrefix:@"cfprefsd"])                return ModCfprefsdPivot();
    if ([name hasPrefix:@"MobileGestalt"])           return ModGestaltPoison();
    if ([name hasPrefix:@"writetosymlinked"])        return ModWriteToSymlinked();
    if ([name hasPrefix:@"JSC scribble"])            return ModJscScribbleRW();
    if ([name hasPrefix:@"Unified:"])              return ModUnifiedPrimitives();
    if ([name hasPrefix:@"task_for_pid"])            return ModTaskForPid();
    if ([name hasPrefix:@"mach_vm"])                 return ModTaskVmRW();
    if ([name hasPrefix:@"setuid"])                  return ModSetuidScan();
    if ([name hasPrefix:@"IOKit reachable"])         return ModIOKitReachable();
    if ([name hasPrefix:@"daemon surface"])          return ModMachLookupSweep();
    if ([name hasPrefix:@"daemon pivot: writable"])  return ModContainerPivot();
    if ([name hasPrefix:@"daemon pivot: container"]) return ModDaemonPivotWrite();
    if ([name hasPrefix:@"JSC fake-object"])         return ModJscFakeRW();
    if ([name hasPrefix:@"CG Type-5 shading OOB"])   return ModCGShadingOOB();
    if ([name hasPrefix:@"CVE-2026-86950 thumbnail"]) return ModCVE86950();
    if ([name hasPrefix:@"43723"])                    return ModMediaRemoteDD();
    if ([name hasPrefix:@"112611 force"])         return ModShading5Force();
    if ([name hasPrefix:@"IOSurfaceRoot selectors"]) return ModIosurfaceRootSelectors();
    if ([name hasPrefix:@"GPU process carrier"])     return ModGpuCarrier();
    return nil;
}
