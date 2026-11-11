#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <sys/stat.h>
#import "Root.h"
#import "Modules.h"

static BOOL g_rootObtained = NO;

// MARK: - live root probe
int RootUid(void) { return (int)getuid(); }

// The only honest test: try to create a file in a directory that only root can
// write to. getuid() alone can lie (setuid binaries), so both are checked.
static BOOL rootWriteWorks(void) {
    const char *targets[] = { "/private/var/root", "/var/root", "/", NULL };
    for (int i = 0; targets[i]; i++) {
        char p[256];
        snprintf(p, sizeof p, "%s/.rootsuite_probe", targets[i]);
        int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) { close(fd); unlink(p); return YES; }
        if (errno == EACCES || errno == EPERM) continue;      // keep looking
    }
    return NO;
}

BOOL RootProbe(void) {
    if (geteuid() == 0) { g_rootObtained = YES; return YES; }
    if (rootWriteWorks()) { g_rootObtained = YES; return YES; }
    return NO;
}

void RootSetObtained(BOOL yes) {
    if (yes) g_rootObtained = YES;
}

BOOL RootWasObtained(void) { return g_rootObtained; }

NSString *RootStateString(void) {
    if (RootProbe()) return [NSString stringWithFormat:@"root: ДА (uid=%d)", (int)getuid()];
    return [NSString stringWithFormat:@"root: НЕТ (uid=%d)", (int)getuid()];
}

// MARK: - download helper (small, cancellation-safe, no progress UI churn)
static NSString *downloadTo(NSString *url, NSString *dest) {
    NSURL *u = [NSURL URLWithString:url];
    if (!u) return @"bad url";
    NSURLRequest *req = [NSURLRequest requestWithURL:u
                                         cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                     timeoutInterval:60];
    NSError *err = nil;
    NSData *d = [NSURLConnection sendSynchronousRequest:req returningResponse:nil error:&err];
    if (err || !d) return [NSString stringWithFormat:@"download failed: %@", err.localizedDescription ?: @"?"];
    if (![d writeToFile:dest atomically:YES]) return @"write failed";
    return nil;
}

// MARK: - Sileo
//   Official Sileo builds ship as a .deb (Cydia/Telesphoreo repo).  With uid 0 we
//   install it with dpkg; without root we keep the package staged in the container
//   so a later privileged run can finish the job.
NSString *InstallSileo(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *deb  = [docs stringByAppendingPathComponent:@"sileo.deb"];
    AveLog(@"    sileo: скачиваю пакет…");
    NSString *e = downloadTo(@"https://repo.barkbark.ninja/debs/sileo_2.5_iphoneos-arm.deb", deb);
    if (e) { AveLog([NSString stringWithFormat:@"    sileo: %@", e]); return e; }
    unsigned long long sz = [[NSFileManager defaultManager] attributesOfItemAtPath:deb error:nil].fileSize;
    AveLog([NSString stringWithFormat:@"    sileo: пакет готов (%llu КБ) — %@", sz / 1024, deb]);

    if (!RootProbe()) {
        AveSetStatus(@"root: НЕТ — сначала эксплойт");
        AveLog(@"    sileo: root не получен, установка отложена (пакет сохранён)");
        return @"жду root: пакет скачан, установка невозможна без uid 0";
    }
    AveSetStatus(@"root: ДА — ставлю Sileo");
    AveLog(@"    sileo: uid 0 получен, ставлю через dpkg…");
    int rc = system("dpkg -i /var/mobile/Documents/sileo.deb 2>&1 || /usr/bin/dpkg -i /var/mobile/Documents/sileo.deb 2>&1");
    AveLog([NSString stringWithFormat:@"    sileo: dpkg rc=%d", rc]);
    return rc == 0 ? @"Sileo установлен (dpkg)" : @"Sileo: dpkg не disponible — нужен полноценный jailbreak";
}

// MARK: - Apple Terminal
//   iOS has no Terminal app; the standard way to get one is a jailbreak package
//   (e.g. NewTerm / a terminal from Chariz).  We fetch it, and install it the same
//   way: needs uid 0.
NSString *InstallTerminal(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *deb  = [docs stringByAppendingPathComponent:@"terminal.deb"];
    AveLog(@"    terminal: скачиваю пакет…");
    NSString *e = downloadTo(@"https://apt.bingner.com/debs/newterm3_2.6_iphoneos-arm.deb", deb);
    if (e) { AveLog([NSString stringWithFormat:@"    terminal: %@", e]); return e; }
    unsigned long long sz = [[NSFileManager defaultManager] attributesOfItemAtPath:deb error:nil].fileSize;
    AveLog([NSString stringWithFormat:@"    terminal: пакет готов (%llu КБ) — %@", sz / 1024, deb]);

    if (!RootProbe()) {
        AveSetStatus(@"root: НЕТ — сначала эксплойт");
        AveLog(@"    terminal: root не получен, установка отложена (пакет сохранён)");
        return @"жду root: пакет скачан, установка невозможна без uid 0";
    }
    AveSetStatus(@"root: ДА — ставлю Terminal");
    AveLog(@"    terminal: uid 0 получен, ставлю через dpkg…");
    int rc = system("dpkg -i /var/mobile/Documents/terminal.deb 2>&1 || /usr/bin/dpkg -i /var/mobile/Documents/terminal.deb 2>&1");
    AveLog([NSString stringWithFormat:@"    terminal: dpkg rc=%d", rc]);
    return rc == 0 ? @"Terminal установлен (dpkg)" : @"Terminal: dpkg не disponible — нужен полноценный jailbreak";
}
