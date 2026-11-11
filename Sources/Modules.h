#import <Foundation/Foundation.h>

#ifndef MODULES_H
#define MODULES_H

#ifdef __cplusplus
extern "C" {
#endif

// ---- every exploit / root path we have, as a runnable module ---------------
NSString *ModWorseQuery(void);            // forcequitOS worse_query  PUBLIC/UNPATCHED
NSString *ModBlSbx(void);                 // hanakim3945 bl_sbx       PUBLIC (26.2b1)
NSString *ModSandboxEscape(void);        // bad_query container escape PROVEN
NSString *ModRootFiles(void);            // read root-owned files      PROVEN
NSString *ModWebKitUAF(void);            // CVE-2025-43529 addrof/fake PROVEN
NSString *ModDyldOracle(void);           // CVE-2026-20700 PAC oracle  PROVEN
NSString *ModIOHID(void);                // float->int sites           MEASURED
NSString *ModIOSurface(void);            // format-class consistency  MEASURED
NSString *ModAVE2(void);                  // AppleAVE2 user client     GATED
NSString *ModKernelPosture(void);        // bootargs/AMFI/CSR/tfp0     MEASURED
NSString *ModPrivilegedServices(void);   // Mach services an app can open TEST
NSString *ModGPU(void);                   // WebKit WebGL fingerprint  MEASURED
NSString *ModIOSkywalk(void);            // varint off-by-one (LAN)    TEST
NSString *ModND6(void);                   // ND6 options (LAN)         TEST
NSString *ModHFS(void);                   // flag-nibble diff evidence DIFF

// dispatcher from the UI's module name
NSString *RunModule(NSString *name);

#ifdef __cplusplus
}
#endif
#endif
