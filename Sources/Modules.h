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

// dispatchers
NSString *RunModule(NSString *name);
NSString *RunRootPath(NSString *name);

#ifdef __cplusplus
}
#endif
#endif
