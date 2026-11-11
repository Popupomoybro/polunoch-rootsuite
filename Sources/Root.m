#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <unistd.h>
#import <fcntl.h>
#import <errno.h>
#import <string.h>
#import <stdlib.h>
#import <spawn.h>
#import <sys/wait.h>
#import <sys/stat.h>
#import "Root.h"
#import "Modules.h"
#import "AppDelegate.h"

static BOOL g_rootObtained = NO;

// MARK: - live root probe
int RootUid(void) { return (int)getuid(); }

// The only honest test: try to create a file in a directory that only root can
// write to.  getuid() alone can lie (setuid binaries), so both are checked.
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

void RootSetObtained(BOOL yes) { if (yes) g_rootObtained = YES; }

BOOL RootWasObtained(void) { return g_rootObtained; }

NSString *RootStateString(void) {
    if (RootProbe()) return [NSString stringWithFormat:@"root: YES (uid=%d)", (int)getuid()];
    return [NSString stringWithFormat:@"root: NO (uid=%d)", (int)getuid()];
}

// MARK: - helpers
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

// system() is unavailable on iOS, so a child process needs posix_spawn.
static int runTool(const char *path, const char *const argv[]) {
    pid_t pid = 0;
    int rc = posix_spawn(&pid, path, NULL, NULL, (char *const *)argv, NULL);
    if (rc != 0) return -1;
    int st = 0;
    if (waitpid(pid, &st, 0) != pid) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -2;
}

static NSString *installDeb(NSString *name, NSString *debPath) {
    const char *path = debPath.UTF8String;
    const char *a1[] = { "/usr/bin/dpkg", "-i", path, NULL };
    const char *a2[] = { "/bin/dpkg", "-i", path, NULL };
    int rc = runTool("/usr/bin/dpkg", a1);
    if (rc != 0) rc = runTool("/bin/dpkg", a2);
    AveLog([NSString stringWithFormat:@"    %@: dpkg rc=%d", name, rc]);
    if (rc == 0) return [NSString stringWithFormat:@"%@ installed (dpkg)", name];
    return [NSString stringWithFormat:@"%@: dpkg unavailable (rc=%d) - a full jailbreak is needed", name, rc];
}

// MARK: - Sileo
NSString *InstallSileo(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *deb  = [docs stringByAppendingPathComponent:@"sileo.deb"];
    AveLog(@"    sileo: downloading the package...");
    NSString *e = downloadTo(@"https://repo.barkbark.ninja/debs/sileo_2.5_iphoneos-arm.deb", deb);
    if (e) { AveLog([NSString stringWithFormat:@"    sileo: %@", e]); return e; }
    unsigned long long sz = [[NSFileManager defaultManager] attributesOfItemAtPath:deb error:nil].fileSize;
    AveLog([NSString stringWithFormat:@"    sileo: package ready (%llu KB) -> %@", sz / 1024, deb]);

    if (!RootProbe()) {
        AveSetStatus(@"no root yet - run the exploits first");
        AveLog(@"    sileo: no uid 0, install deferred (package kept in the container)");
        return @"waiting for root: package downloaded, install needs uid 0";
    }
    AveSetStatus(@"root obtained - installing Sileo");
    AveLog(@"    sileo: uid 0 confirmed, installing with dpkg...");
    return installDeb(@"Sileo", deb);
}

// MARK: - Terminal
NSString *InstallTerminal(void) {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *deb  = [docs stringByAppendingPathComponent:@"terminal.deb"];
    AveLog(@"    terminal: downloading the package...");
    NSString *e = downloadTo(@"https://apt.bingner.com/debs/newterm3_2.6_iphoneos-arm.deb", deb);
    if (e) { AveLog([NSString stringWithFormat:@"    terminal: %@", e]); return e; }
    unsigned long long sz = [[NSFileManager defaultManager] attributesOfItemAtPath:deb error:nil].fileSize;
    AveLog([NSString stringWithFormat:@"    terminal: package ready (%llu KB) -> %@", sz / 1024, deb]);

    if (!RootProbe()) {
        AveSetStatus(@"no root yet - run the exploits first");
        AveLog(@"    terminal: no uid 0, install deferred (package kept in the container)");
        return @"waiting for root: package downloaded, install needs uid 0";
    }
    AveSetStatus(@"root obtained - installing Terminal");
    AveLog(@"    terminal: uid 0 confirmed, installing with dpkg...");
    return installDeb(@"Terminal", deb);
}
