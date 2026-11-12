#import <Foundation/Foundation.h>

#ifndef UTIL_H
#define UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

// Shared formatting helper (printf-style -> NSString), used by every module.
static inline NSString *S(NSString *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    return s;
}

// Reads a JavaScript source that lives in its OWN .js file inside the bundle.
// The JSC scripts used to be embedded as C raw string literals, but that put
// arbitrary JS (with braces, quotes, @ and //) inside the Objective-C lexer,
// which is a standing invitation for parser desyncs.  Keeping the JS in its
// own file removes every escaping rule: edit the .js and nothing else changes.
static inline NSString *LoadJS(NSString *name) {
    NSString *path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:name];
    NSData *d = [NSData dataWithContentsOfFile:path];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}

#ifdef __cplusplus
}
#endif
#endif
