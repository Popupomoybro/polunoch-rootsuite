#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_port.h>
#import <CoreFoundation/CoreFoundation.h>
#import <IOKit/IOKitLib.h>
#import "Modules.h"
#import "Root.h"
#import "Util.h"
#import "AppDelegate.h"

// ===========================================================================
// Top public kernel attack surfaces (from the agent research), measured as
// reachability ONLY — none of them fires a write, because every one of them has
// a demonstrated panic primitive.
//   1. AppleJPEGDriver   CVE-2026-20687  startDecoder timeout UAF (public PoC)
//                                                          (fixed 26.3/26.4)
//   2. AppleM2ScalerCSCDriver CVE-2026-43655 shared-scheduler UAF, public
//                                                          fixed-offset write +0x1fe4
//   3. AppleSEPKeyStore / AppleKeyStoreUserClient CVE-2026-20637 + close-UAF
//                                                          on selector 10 (fixed 26.3)
//   4. IOTimeSyncFamily CVE-2026-28969 close/externalMethod race: a panic
//      weapon (100% reproducible panic, x25=5/6, FAR=0xF0) - reported only.
// ===========================================================================

static int openUserClient(const char *cls, int type, io_connect_t *out) {
    CFMutableDictionaryRef m = IOServiceMatching(cls);
    if (!m) return -1;
    io_service_t d = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!d) return -2;
    kern_return_t kr = IOServiceOpen(d, mach_task_self(), type, out);
    IOObjectRelease(d);
    return kr == KERN_SUCCESS ? 0 : kr;
}

NSString *ModAppleJPEGDriver(void) {
    io_connect_t c = 0;
    int r = openUserClient("AppleJPEGDriver", 0, &c);
    if (r != 0)
        return S(@"AppleJPEGDriver: user client not openable at type 0 (kr=%#x)", r);
    // selector ABI exists; firing is not done here (panic risk).
    // The known-good write routes all start from startDecoder's timeout path.
    AveLog(@"    AppleJPEGDriver: user client OPEN - selector ABI present "
           @"(startDecoder/timeout is the vulnerable path; nothing fired)");
    IOServiceClose(c);
    return @"AppleJPEGDriver: OPEN - CVE-2026-20687 surface present, no write fired";
}

NSString *ModAppleM2ScalerCSC(void) {
    io_connect_t c = 0;
    int r = openUserClient("AppleM2ScalerCSCDriver", 0, &c);
    if (r != 0)
        return S(@"AppleM2ScalerCSCDriver: not openable at type 0 (kr=%#x)", r);
    AveLog(@"    AppleM2ScalerCSCDriver: OPEN - shared scheduler at a fixed offset "
           @"(+0x1fe4) is the public write site; nothing fired");
    IOServiceClose(c);
    return @"AppleM2ScalerCSCDriver: OPEN - CVE-2026-43655 surface present, no write fired";
}

NSString *ModAppleKeyStore(void) {
    for (const char *cls = "AppleKeyStore"; ; ) {
        io_connect_t c = 0;
        int r = openUserClient(cls, 0, &c);
        if (r != 0) break;
        AveLog(@"    AppleKeyStoreUserClient: OPEN at type 0 "
               @"(close-UAF on selector 10 is the public crash; nothing fired)");
        IOServiceClose(c);
        return @"AppleKeyStore: OPEN - CVE-2026-20637 / close-UAF surface present, no race fired";
    }
    return @"AppleKeyStore: user client not openable at type 0";
}

NSString *ModIOTimeSyncReach(void) {
    CFMutableDictionaryRef m = IOServiceMatching("IOTimeSyncClockManager");
    io_service_t d = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : 0;
    if (!d) {
        if (m) CFRelease(m);
        m = IOServiceMatching("IOTimeSyncFamily");
        d = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : 0;
    }
    BOOL present = (d != 0);
    if (d) IOObjectRelease(d);
    if (m) CFRelease(m);
    if (!present)
        return @"IOTimeSyncFamily: service not found (the public panic PoC needs it)";
    // deliberately NOT opened: the race is a 100% reproducible kernel panic.
    return @"IOTimeSyncFamily: service PRESENT - never opened (the race is a "
           @"guaranteed panic: FAR=0xF0, x25=5/6)";
}

// ---------------------------------------------------------------------------
NSString *RunKernelPath(NSString *name) {
    if ([name hasPrefix:@"AppleJPEGDriver"])       return ModAppleJPEGDriver();
    if ([name hasPrefix:@"AppleM2ScalerCSCDriver"]) return ModAppleM2ScalerCSC();
    if ([name hasPrefix:@"AppleKeyStore"])          return ModAppleKeyStore();
    if ([name hasPrefix:@"IOTimeSync"])             return ModIOTimeSyncReach();
    return nil;
}
