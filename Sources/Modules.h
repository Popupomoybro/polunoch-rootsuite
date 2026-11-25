#import <Foundation/Foundation.h>

#ifndef MODULES_H
#define MODULES_H

#ifdef __cplusplus
extern "C" {
#endif

// ---- container / sandbox --------------------------------------------------
NSString *ModWorseQuery(void);      // PUBLIC worse_query container escape
NSString *ModBlSbx(void);           // PUBLIC bl_sbx (write as uid 501)
NSString *ModSandboxEscape(void);  // PROVEN bad_query escape
NSString *ModRootFiles(void);       // PROVEN root-owned file reads

// ---- kernel / credential surface (each is a step to uid 0) ----------------
NSString *ModTaskForPid(void);      // task port of root processes -> their R/W
NSString *ModTaskVmRW(void);        // mach_vm R/W primitives
NSString *ModSetuidScan(void);      // setuid-root binaries reachable
NSString *ModIOKitReachable(void);  // IOKit user clients the app can open

// ---- daemon pivot surface -------------------------------------------------
NSString *ModMachLookupSweep(void); // privileged Mach services answering
NSString *ModContainerPivot(void);  // writable daemon paths

// ---- JSC / WebKit chain ---------------------------------------------------
NSString *ModWebKitUAF(void);       // PROVEN addrof + fakeobj
NSString *ModJscStructScan(void);    // structure ID -> in-object R/W
NSString *ModDyldOracle(void);      // PROVEN dyld PAC signing oracle

// ---- measured / kernel-diff findings --------------------------------------
NSString *ModKernelPosture(void);
NSString *ModIOHID(void);
NSString *ModIOSurface(void);
NSString *ModAVE2(void);
NSString *ModGPU(void);
NSString *ModIOSkywalk(void);
NSString *ModND6(void);
NSString *ModHFS(void);
NSString *ModCoreDevice(void);

// ---- the last mile (unpatched app->root bugs on this build) ----------------
NSString *ModCoreServices20615(void);
NSString *ModCoreServices20617(void);
NSString *ModKernelRoot(void);
NSString *ModLibxpc20667(void);
NSString *ModCfprefsdPivot(void);
NSString *ModGestaltPoison(void);
NSString *ModWriteToSymlinked(void);

// ---- cross-file implementations (RootPaths.m / RootPaths2.m) ---------------
NSString *ModDaemonPivotWrite(void);
NSString *ModJscFakeRW(void);
NSString *ModIosurfaceRootSelectors(void);
NSString *ModGpuCarrier(void);


// ---- top public kernel attack surfaces (measured, never fired) -----------
NSString *ModAppleJPEGDriver(void);
NSString *ModAppleM2ScalerCSC(void);
NSString *ModAppleKeyStore(void);
NSString *ModIOTimeSyncReach(void);
NSString *RunKernelPath(NSString *name);

NSString *ModJscScribbleRW(void);

NSString *ModUnifiedPrimitives(void);

NSString *ModKernelSelectorSweep(void);
NSString *ModAppGroupDiag(void);
NSString *ModCGShadingOOB(void);   // CoreGraphics Type-5 shading OOB write (CVE-2026-112611)
NSString *ModCVE86950(void);       // ImageIO PDF thumbnail heap OOB write (CVE-2026-86950)
NSString *ModMediaRemoteDD(void);  // CVE-2026-43723: mediaremoted path traversal -> root write
NSString *ModShading5Force(void);  // CVE-2026-112611: mmap-force aimed write (public V545 recipe)
NSString *ModIsurfUAF(void);       // CVE-2026-112477: IOSurfaceRootUserClient registry UAF (kernel)
NSString *ModIsurfUAF2(void);      // phase 2: the user-client lifetime UAF the device panic proved - reclaim groom
NSString *ModIsurfUAF3(void);      // phase 4: the IOSurface deref control (far = app mapping + 8)
NSString *ModIsurfUAFAt(int unit); // direct entry at a phase-2 unit (3 = the panic shape, 6 = the racer)
NSString *ModIOGPUUAFOracle(void); // CVE-2026-64788: overflow IOSurface -> stale GPU resource entry (oracle, A14-tested PoC)
NSString *ModVmMapWrap(void);      // CVE-2025-46285: vm_map timestamp (32-bit) wrap rate measurement
NSString *ModAioRace(void);        // family B reproducer: aio_workq_entry teardown race (48 panics)
NSString *ModJpegUAF(void);        // CVE-2026-20687: AppleJPEGDriver startDecoder timeout UAF (public PoC)
NSString *ModAksUAF(void);         // CVE-2026-20637: AppleSEPKeyStore IOCommandGate UAF (public PoC, tested 26.1-26.2)
NSString *ModAksReclaim(void);     // 20637 + kalloc.80 canary reclaim spray (device-confirmed UAF)
// dispatchers
NSString *RunModule(NSString *name);
NSString *RunRootPath(NSString *name);

#ifdef __cplusplus
}
#endif
#endif
