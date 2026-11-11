#import <Foundation/Foundation.h>

#ifndef MODULES_H
#define MODULES_H

#ifdef __cplusplus
extern "C" {
#endif

// ---- every exploit / root path we have, as a runnable module ---------------
NSString *ModSandboxEscape(void);        // bad_query sandbox escape          PROVEN
NSString *ModRootFiles(void);            // read root-owned files             PROVEN
NSString *ModWebKitUAF(void);            // CVE-2025-43529 addrof/fakeobj     PROVEN
NSString *ModDyldOracle(void);           // CVE-2026-20700 PAC signing oracle PROVEN
NSString *ModIOHID(void);                // float->int truncation sites      MEASURED
NSString *ModIOSurface(void);            // format-class consistency         MEASURED
NSString *ModAVE2(void);                  // AppleAVE2 user client           GATED
NSString *ModKernelPosture(void);        // bootargs/AMFI/CSR/tfp0           MEASURED
NSString *ModPrivilegedServices(void);   // Mach services an app can open    TEST
NSString *ModGPU(void);                   // WebKit WebGL fingerprint         MEASURED
NSString *ModIOSkywalk(void);            // varint off-by-one (LAN)          TEST
NSString *ModND6(void);                   // ND6 option handling (LAN)        TEST
NSString *ModHFS(void);                   // flag-nibble diff evidence        DIFF

// dispatcher from the UI's module name
NSString *RunModule(NSString *name);

#ifdef __cplusplus
}
#endif
#endif
