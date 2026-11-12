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

// dispatchers
NSString *RunModule(NSString *name);
NSString *RunRootPath(NSString *name);

#ifdef __cplusplus
}
#endif
#endif
