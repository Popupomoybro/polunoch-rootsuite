#ifndef JSRUN_H
#define JSRUN_H

#import <Foundation/Foundation.h>
#import <JavaScriptCore/JavaScriptCore.h>
#import "AppDelegate.h"

// Where the device can fetch a live copy of a script.  Serving it over HTTP
// means a JS change costs seconds, not a CI run + Sideloadly install.
#ifndef JS_LIVE_BASE
#define JS_LIVE_BASE @"http://192.168.1.125:8098"
#endif

// ---------------------------------------------------------------------------
// Run a script inside our own JavaScriptCore on a thread with a REAL stack.
//
// This is not a nicety.  JSC derives its JavaScript recursion limit from
// pthread_get_stacksize_np(): on a libdispatch worker thread (~512 KB) the
// PoC's 10000-frame GC-pressure recursion dies immediately with
//   RangeError: Maximum call stack size exceeded
// before it can free a single slot, while on a WebKit WebThread the stack is
// megabytes -- which is where the trigger was measured to work.  The device
// log proves it: two consecutive runs reported exactly that RangeError from
// the warmup phase and the trigger never fired in 4875 shaved rounds.
// ---------------------------------------------------------------------------
static inline NSString *RunJSBigStack(NSString *src, NSString *tag, NSInteger timeoutSec) {
    // The answer travels inside a holder that BOTH the caller and the block keep
    // alive.  A plain `__block NSString *res` is released the moment the thread
    // destroys its block -- which happens immediately after the semaphore
    // signal, i.e. while the caller is still about to read res.  The object is
    // deallocated under the caller's feet and formatting it BRKs in
    // objc_opt_respondsToSelector (device-crash-classic, seen at
    // "scribble result: %@").  The array survives both releases.
    NSMutableArray *box = [NSMutableArray array];
    if (src && src.length) {
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        NSThread *t = [[NSThread alloc] initWithBlock:^{
            @autoreleasepool {
                JSContext *ctx = [[JSContext alloc] init];
                ctx[@"aveStep"] = ^(id s) {
                    NSString *line = [s isKindOfClass:[NSString class]] ? s : @"?";
                    AveLog([NSString stringWithFormat:@"    js. %@", line]);
                    AvePost([NSString stringWithFormat:@"%@ STEP %@", tag, line]);
                };
                id answer = nil;
                @try {
                    JSValue *v = [ctx evaluateScript:src];
                    JSValue *exc = [ctx exception];
                    if (exc) {
                        // toObject() is the sanctioned bridge and does not re-enter
                        // JS the way -[JSValue toString] does.
                        id o = [exc toObject];
                        answer = [o isKindOfClass:[NSString class]] ? o : nil;
                    } else if (v) {
                        if ([v isKindOfClass:[NSString class]]) answer = v;
                        else {
                            id o = [v toObject];
                            answer = [o isKindOfClass:[NSString class]] ? o : nil;
                        }
                    }
                } @catch (NSException *e) {
                    answer = [NSString stringWithFormat:@"exception %@", e.reason];
                }
                ctx = nil;
                // only ever a real NSString leaves this thread
                [box addObject:[answer isKindOfClass:[NSString class]] ? answer : @"(non-string)"];
            }
            dispatch_semaphore_signal(done);
        }];
        t.stackSize = 8 * 1024 * 1024;          // like a WebKit WebThread
        [t start];
        if (dispatch_semaphore_wait(done,
                dispatch_time(DISPATCH_TIME_NOW, (int64_t)timeoutSec * NSEC_PER_SEC)) != 0) {
            AvePost([NSString stringWithFormat:@"%@ TIMEOUT after %lds (thread kept running)",
                     tag, (long)timeoutSec]);
        }
    }
    return box.count ? box[0] : @"(no script)";
}

// Prefer a live copy served over HTTP, fall back to the copy in the bundle.
static inline NSString *LoadJS(NSString *name) {
    if (!name) return nil;
    NSString *url = [NSString stringWithFormat:@"%@/%@?v=%f", JS_LIVE_BASE, name,
                     [NSDate timeIntervalSinceReferenceDate]];
    NSURLRequest *req = [NSURLRequest requestWithURL:[NSURL URLWithString:url]
                                         cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                     timeoutInterval:8];
    NSURLResponse *resp = nil;
    NSError *err = nil;
    @try {
        NSData *d = [NSURLConnection sendSynchronousRequest:req returningResponse:&resp error:&err];
        NSString *s = d.length ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
        // a 404 page is HTML, not JavaScript: only take real source
        if (s.length >= 64 && ![s containsString:@"<html"] && ![s containsString:@"<!DOCTYPE"]) {
            AvePost([NSString stringWithFormat:@"JS %@ live (%lu bytes)", name, (unsigned long)s.length]);
            return s;
        }
    } @catch (NSException *e) { }
    NSString *path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:name];
    NSData *bd = [NSData dataWithContentsOfFile:path];
    NSString *bs = bd.length ? [[NSString alloc] initWithData:bd encoding:NSUTF8StringEncoding] : nil;
    // a missing file comes back as the server's 404 HTML page, which is longer
    // than any sanity floor: reject anything that is not JavaScript
    if (bs && ([bs containsString:@"<html"] || [bs containsString:@"<!DOCTYPE"] ||
               [bs containsString:@"404"]))
        bs = nil;
    AvePost([NSString stringWithFormat:@"JS %@ bundle (%@)", name,
             bs ? [NSString stringWithFormat:@"%lu bytes", (unsigned long)bs.length] : @"MISSING"]);
    return bs;
}

#endif
