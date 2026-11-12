// ---------------------------------------------------------------------------
// Selector sweep on the user clients that ARE open (device-verified).
// The device run showed: IOSurfaceRoot answers 0xE00002C2 (NotPrivileged) for
// every selector at type 0, but AppleJPEGDriver, AppleM2ScalerCSCDriver,
// AppleKeyStore and AppleCLCD2 all returned IOServiceOpen=0 (KERN_SUCCESS).
// Those three are exactly the surfaces with public PoCs:
//   AppleJPEGDriver    CVE-2026-20687  startDecoder timeout UAF
//   AppleM2ScalerCSC   CVE-2026-43655  fixed-offset write at +0x1fe4
//   AppleKeyStore      CVE-2026-20637 / close-UAF on selector 10
// So the question that matters is: which selectors does each of them ANSWER?
//
// Safety: a zeroed, minimal input struct and a stop-on-first-error policy. The
// public PoCs are deliberate kernel panics that need crafted structures and
// thread races; a single zeroed call to a file-backed driver returns an error
// code instead.  A wider sweep is opt-in via POC_FULL=1.
// ---------------------------------------------------------------------------
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <mach/mach_port.h>
#import <IOKit/IOKitLib.h>
#import "Modules.h"
#import "Root.h"
#import "Util.h"
#import "AppDelegate.h"

static int sweepClient(const char *cls, int maxSel) {
    CFMutableDictionaryRef m = IOServiceMatching(cls);
    if (!m) return -1;
    io_service_t d = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!d) { CFRelease(m); return -2; }
    io_connect_t c = 0;
    kern_return_t kr = IOServiceOpen(d, mach_task_self(), 0, &c);
    IOObjectRelease(d);
    CFRelease(m);
    if (kr != KERN_SUCCESS || !c) return (int)kr;

    int answered = 0;
    uint64_t in[8];
    uint64_t out[8];
    for (uint32_t sel = 0; sel < maxSel; sel++) {
        memset(in, 0, sizeof in);
        memset(out, 0, sizeof out);
        size_t outSz = sizeof out;
        kern_return_t r = IOConnectCallMethod(c, sel, in, 0, NULL, 0,
                                              out, &outSz, NULL, NULL);
        AveLog(S(@"    %-22s sel %-3u -> %#x", cls, sel, r));
        // codes that mean "this selector exists and answered"
        if (r == KERN_SUCCESS || r == kIOReturnBadArgument ||
            r == kIOReturnVMError || r == kIOReturnNoSpace ||
            r == kIOReturnCannotWire || r == kIOReturnNotAligned) {
            answered++;
        }
        if (r == kIOReturnUnsupported || r == kIOReturnNotPrivileged) continue;
        if (r == kIOReturnBadArgument) break;      // stop early: deeper args get riskier
    }
    IOServiceClose(c);
    return answered;
}

NSString *ModKernelSelectorSweep(void) {
    const char *full = getenv("POC_FULL");
    int max = (full && *full == '1') ? 32 : 12;
    AveLog(S(@"    selector sweep on the OPEN user clients (max %d per class)", max));

    struct { const char *cls; const char *cve; } C[] = {
        {"AppleJPEGDriver", "CVE-2026-20687 (startDecoder UAF)"},
        {"AppleM2ScalerCSCDriver", "CVE-2026-43655 (write +0x1fe4)"},
        {"AppleKeyStore", "CVE-2026-20637 / close-UAF sel 10"},
    };
    int total = 0;
    for (unsigned i = 0; i < sizeof(C)/sizeof(C[0]); i++) {
        AveLog(S(@"  -- %s (%s)", C[i].cls, C[i].cve));
        int a = sweepClient(C[i].cls, max);
        if (a < 0) AveLog(S(@"    %-22s not openable (kr=%#x)", C[i].cls, -a));
        else { total += a; AveLog(S(@"    %-22s %d selectors ANSWERED", C[i].cls, a)); }
    }
    AveSetStatus(total ? S(@"kernel: %d selectors answered across 3 clients", total)
                       : @"kernel: all selectors refused");
    return S(@"kernel selector sweep: %d selectors answered across 3 OPEN user clients "
             @"(JPEG/M2Scaler/KeyStore)", total);
}

// ---------------------------------------------------------------------------
// App-group diagnostics: WHY the group container is unavailable, and what we do
// have (our own container path is the fallback pivot base).
// ---------------------------------------------------------------------------
NSString *ModAppGroupDiag(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    NSMutableArray *cands = [NSMutableArray array];
    [cands addObject:[NSString stringWithFormat:@"group.%@", bid]];
    [cands addObject:bid];
    [cands addObject:@"group.cc.forcequit.bad-query"];
    [cands addObject:[NSString stringWithFormat:@"group.%@", @"polunoch"]];
    NSString *found = nil;
    for (NSString *g in cands) {
        NSURL *u = [fm containerURLForSecurityApplicationGroupIdentifier:g];
        AveLog(S(@"    group %-44s -> %@", g, u ? u.path : @"nil"));
        if (u && !found) found = g;
    }
    AveLog([NSString stringWithFormat:@"    NSHomeDirectory: %@",
           [NSURL fileURLWithPath:NSHomeDirectory()].path]);
    NSURL *docs = [NSURL fileURLWithPath:
                   [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                        NSUserDomainMask, YES) firstObject]];
    AveLog([NSString stringWithFormat:@"    Documents:        %@", docs.path]);
    if (found)
        return S(@"app group AVAILABLE: %@ (worse_query can run against it)", found);
    return @"app group container NOT created by installd - our own app container "
           @"is the pivot base instead";
}

// ---------------------------------------------------------------------------
// The four original reachability probes (device-verified as OPEN).
// ---------------------------------------------------------------------------
static int openUserClient(const char *cls, int type, io_connect_t *out) {
    CFMutableDictionaryRef m = IOServiceMatching(cls);
    if (!m) return -1;
    io_service_t d = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (!d) { CFRelease(m); return -2; }
    kern_return_t kr = IOServiceOpen(d, mach_task_self(), type, out);
    IOObjectRelease(d);
    CFRelease(m);
    return kr == KERN_SUCCESS ? 0 : kr;
}

NSString *ModAppleJPEGDriver(void) {
    io_connect_t c = 0;
    int r = openUserClient("AppleJPEGDriver", 0, &c);
    if (r != 0)
        return S(@"AppleJPEGDriver: user client not openable at type 0 (kr=%#x)", r);
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
    io_connect_t c = 0;
    int r = openUserClient("AppleKeyStore", 0, &c);
    if (r != 0)
        return S(@"AppleKeyStore: not openable at type 0 (kr=%#x)", r);
    AveLog(@"    AppleKeyStoreUserClient: OPEN at type 0 "
           @"(close-UAF on selector 10 is the public crash; nothing fired)");
    IOServiceClose(c);
    return @"AppleKeyStore: OPEN - CVE-2026-20637 / close-UAF surface present, no race fired";
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
    if ([name hasPrefix:@"AppleJPEGDriver"])        return ModAppleJPEGDriver();
    if ([name hasPrefix:@"AppleM2ScalerCSCDriver"]) return ModAppleM2ScalerCSC();
    if ([name hasPrefix:@"AppleKeyStore"])          return ModAppleKeyStore();
    if ([name hasPrefix:@"IOTimeSync"])             return ModIOTimeSyncReach();
    if ([name hasPrefix:@"kernel selector"])        return ModKernelSelectorSweep();
    if ([name hasPrefix:@"app group"])              return ModAppGroupDiag();
    return nil;
}
