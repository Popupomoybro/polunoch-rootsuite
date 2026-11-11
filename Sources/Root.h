#import <Foundation/Foundation.h>

#ifndef ROOT_H
#define ROOT_H

#ifdef __cplusplus
extern "C" {
#endif

// ---- root state ----------------------------------------------------------
// A live probe (not a cached flag): uid/euid plus an actual write attempt into a
// root-only directory.  Kept in one place so the UI pill, the modules and the
// installers all read the same truth.
BOOL RootProbe(void);
NSString *RootStateString(void);          // "root: НЕТ" / "root: ДА (uid=0)"
int  RootUid(void);
void RootSetObtained(BOOL yes);           // recorded when a module really gets uid 0
BOOL RootWasObtained(void);

// ---- installers (Sileo / Apple Terminal) ----------------------------------
// They download the package into the app container, then install it.  Installation
// requires root, so each one reports precisely what is missing instead of failing
// silently.
NSString *InstallSileo(void);
NSString *InstallTerminal(void);

#ifdef __cplusplus
}
#endif
#endif
