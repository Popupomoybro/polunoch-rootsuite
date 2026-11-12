#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import "AppDelegate.h"
#import "Modules.h"
#import "Root.h"

// MARK: - palette
static UIColor *BG(void)     { return [UIColor colorWithRed:0.043 green:0.043 blue:0.059 alpha:1]; }
static UIColor *CARD(void)   { return [UIColor colorWithRed:0.085 green:0.085 blue:0.106 alpha:1]; }
static UIColor *HAIR(void)   { return [UIColor colorWithRed:0.149 green:0.149 blue:0.180 alpha:1]; }
static UIColor *TEXT(void)   { return [UIColor colorWithRed:0.949 green:0.949 blue:0.969 alpha:1]; }
static UIColor *SUB(void)    { return [UIColor colorWithRed:0.557 green:0.557 blue:0.576 alpha:1]; }
static UIColor *ACCENT(void) { return [UIColor colorWithRed:0.188 green:0.820 blue:0.345 alpha:1]; }
static UIColor *WARN(void)   { return [UIColor colorWithRed:1.000 green:0.624 blue:0.039 alpha:1]; }
static UIColor *INFO(void)   { return [UIColor colorWithRed:0.392 green:0.824 blue:1.000 alpha:1]; }
static UIColor *DANGER(void) { return [UIColor colorWithRed:1.000 green:0.271 blue:0.341 alpha:1]; }

static UITextView *g_log = nil;
static UILabel *g_status = nil;
static UILabel *g_rootPill = nil;
static NSString *const kEndpoint = @"http://192.168.1.125:8098/log";

void AveLog(NSString *s) {
    if (!s) s = @"";
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!g_log) return;
        g_log.text = [g_log.text stringByAppendingFormat:@"%@\n", s];
        [g_log scrollRangeToVisible:NSMakeRange(g_log.text.length - 1, 1)];
    });
}

void AveSetStatus(NSString *s) {
    dispatch_async(dispatch_get_main_queue(), ^{ if (g_status) g_status.text = s; });
}

void AveSleep(int ms) { [NSThread sleepForTimeInterval:(double)ms / 1000.0]; }

void AvePost(NSString *s) {
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:kEndpoint]];
    req.HTTPMethod = @"POST"; req.timeoutInterval = 6;
    req.HTTPBody = [[NSString stringWithFormat:@"ROOTSUITE %@", s ?: @""] dataUsingEncoding:NSUTF8StringEncoding];
    [req setValue:@"text/plain" forHTTPHeaderField:@"Content-Type"];
    [[NSURLSession.sharedSession dataTaskWithRequest:req] resume];
}

NSString *AveReadFile(NSString *p) {
    NSData *d = [NSData dataWithContentsOfFile:p];
    return d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : nil;
}

// MARK: - root pill (the app's single source of truth about root)
static void refreshRootPill(void) {
    BOOL have = RootProbe();
    dispatch_async(dispatch_get_main_queue(), ^{
        g_rootPill.text = have ? @"ROOT: YES" : @"ROOT: NO";
        g_rootPill.textColor = have ? [UIColor blackColor] : SUB();
        g_rootPill.backgroundColor = have ? ACCENT() : CARD();
        g_rootPill.layer.borderColor = (have ? ACCENT() : HAIR()).CGColor;
    });
    AveSetStatus(have ? @"root obtained - Sileo/Terminal enabled"
                      : @"no root yet - run the exploits");
    AvePost([NSString stringWithFormat:@"ROOTSTATE %@", have ? @"YES" : @"NO"]);
}

// MARK: - module cell
@interface ModuleCell : UITableViewCell
@property (nonatomic, strong) UILabel *pill, *name, *desc;
@property (nonatomic, strong) UIImageView *tick;
@end

@implementation ModuleCell
- (instancetype)initWithStyle:(UITableViewCellStyle)s reuseIdentifier:(NSString *)rid {
    self = [super initWithStyle:s reuseIdentifier:rid];
    if (self) {
        self.backgroundColor = [UIColor clearColor];
        self.selectionStyle = UITableViewCellSelectionStyleNone;
        UIView *card = [UIView new];
        card.translatesAutoresizingMaskIntoConstraints = NO;
        card.backgroundColor = CARD();
        card.layer.cornerRadius = 14;
        card.layer.borderColor = HAIR().CGColor; card.layer.borderWidth = 0.5;
        [self.contentView addSubview:card];
        self.pill = [UILabel new]; self.pill.translatesAutoresizingMaskIntoConstraints = NO;
        self.pill.font = [UIFont monospacedSystemFontOfSize:8 weight:UIFontWeightBold];
        self.pill.textAlignment = NSTextAlignmentCenter;
        self.pill.layer.cornerRadius = 7; self.pill.clipsToBounds = YES;
        [card addSubview:self.pill];
        self.name = [UILabel new]; self.name.translatesAutoresizingMaskIntoConstraints = NO;
        self.name.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
        self.name.textColor = TEXT(); [card addSubview:self.name];
        self.desc = [UILabel new]; self.desc.translatesAutoresizingMaskIntoConstraints = NO;
        self.desc.font = [UIFont systemFontOfSize:11]; self.desc.textColor = SUB();
        self.desc.numberOfLines = 2; [card addSubview:self.desc];
        self.tick = [UIImageView new]; self.tick.translatesAutoresizingMaskIntoConstraints = NO;
        self.tick.contentMode = UIViewContentModeScaleAspectFit; [card addSubview:self.tick];
        [NSLayoutConstraint activateConstraints:@[
            [card.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:12],
            [card.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-12],
            [card.topAnchor constraintEqualToAnchor:self.contentView.topAnchor constant:4],
            [card.bottomAnchor constraintEqualToAnchor:self.contentView.bottomAnchor constant:-4],
            [self.pill.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:12],
            [self.pill.topAnchor constraintEqualToAnchor:card.topAnchor constant:12],
            [self.pill.widthAnchor constraintEqualToConstant:78], [self.pill.heightAnchor constraintEqualToConstant:16],
            [self.name.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:12],
            [self.name.topAnchor constraintEqualToAnchor:self.pill.bottomAnchor constant:6],
            [self.name.trailingAnchor constraintEqualToAnchor:self.tick.leadingAnchor constant:-10],
            [self.desc.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:12],
            [self.desc.topAnchor constraintEqualToAnchor:self.name.bottomAnchor constant:3],
            [self.desc.trailingAnchor constraintEqualToAnchor:self.tick.leadingAnchor constant:-10],
            [self.desc.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-10],
            [self.tick.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14],
            [self.tick.centerYAnchor constraintEqualToAnchor:card.centerYAnchor],
            [self.tick.widthAnchor constraintEqualToConstant:22], [self.tick.heightAnchor constraintEqualToConstant:22],
        ]];
    }
    return self;
}
- (void)configure:(NSDictionary *)m selected:(BOOL)sel {
    NSString *st = m[@"status"];
    self.pill.text = st;
    UIColor *col = [st isEqualToString:@"PROVEN"] ? ACCENT() : [st isEqualToString:@"MEASURED"] ? INFO()
                 : [st isEqualToString:@"GATED"] ? DANGER() : WARN();
    self.pill.textColor = col;
    self.pill.backgroundColor = [col colorWithAlphaComponent:0.16];
    self.name.text = m[@"name"];
    self.desc.text = m[@"desc"];
    UIGraphicsBeginImageContextWithOptions(CGSizeMake(22, 22), NO, 0);
    CGContextRef c = UIGraphicsGetCurrentContext();
    CGRect r = CGRectMake(2, 2, 18, 18);
    CGContextSetStrokeColorWithColor(c, (sel ? ACCENT() : SUB()).CGColor);
    CGContextSetLineWidth(c, 1.4);
    CGContextAddEllipseInRect(c, r); CGContextStrokePath(c);
    if (sel) {
        CGContextSetStrokeColorWithColor(c, ACCENT().CGColor); CGContextSetLineWidth(c, 2.0);
        CGContextMoveToPoint(c, 7, 11.5); CGContextAddLineToPoint(c, 10.2, 14.6); CGContextAddLineToPoint(c, 15.2, 7.8);
        CGContextStrokePath(c);
    }
    self.tick.image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
}
@end

// MARK: - AppDelegate
@interface AppDelegate () <UITableViewDataSource, UITableViewDelegate>
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = BG();
    UILayoutGuide *g = vc.view.safeAreaLayoutGuide;
    CGFloat w = self.window.bounds.size.width;

    self.titleLabel = [UILabel new]; self.titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.titleLabel.text = @"RootSuite";
    self.titleLabel.font = [UIFont systemFontOfSize:26 weight:UIFontWeightHeavy];
    self.titleLabel.textColor = TEXT();

    self.subtitleLabel = [UILabel new]; self.subtitleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.subtitleLabel.text = @"26.2 beta 1 / 23C5027f / arm64e - every root path";
    self.subtitleLabel.font = [UIFont systemFontOfSize:11]; self.subtitleLabel.textColor = SUB();

    g_rootPill = [UILabel new]; g_rootPill.translatesAutoresizingMaskIntoConstraints = NO;
    g_rootPill.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    g_rootPill.textAlignment = NSTextAlignmentCenter;
    g_rootPill.layer.cornerRadius = 12; g_rootPill.clipsToBounds = YES;
    g_rootPill.layer.borderWidth = 0.5; g_rootPill.layer.borderColor = HAIR().CGColor;

    UIView *div = [UIView new]; div.translatesAutoresizingMaskIntoConstraints = NO; div.backgroundColor = HAIR();

    self.table = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    self.table.translatesAutoresizingMaskIntoConstraints = NO;
    self.table.dataSource = self; self.table.delegate = self;
    self.table.rowHeight = UITableViewAutomaticDimension;
    self.table.estimatedRowHeight = 88;
    self.table.backgroundColor = [UIColor clearColor];
    self.table.separatorStyle = UITableViewCellSeparatorStyleNone;
    self.table.showsVerticalScrollIndicator = NO;
    [self.table registerClass:[ModuleCell class] forCellReuseIdentifier:@"c"];

    self.allButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.allButton.translatesAutoresizingMaskIntoConstraints = NO;
    self.allButton.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    [self.allButton setTitle:@"All" forState:UIControlStateNormal];
    [self.allButton setTitleColor:SUB() forState:UIControlStateNormal];
    self.allButton.backgroundColor = CARD(); self.allButton.layer.cornerRadius = 10;
    self.allButton.layer.borderColor = HAIR().CGColor; self.allButton.layer.borderWidth = 0.5;
    [self.allButton addTarget:self action:@selector(toggleAll) forControlEvents:UIControlEventTouchUpInside];

    self.runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runButton.translatesAutoresizingMaskIntoConstraints = NO;
    self.runButton.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    [self.runButton setTitle:@">>  Run" forState:UIControlStateNormal];
    [self.runButton setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    self.runButton.backgroundColor = ACCENT(); self.runButton.layer.cornerRadius = 10;
    [self.runButton addTarget:self action:@selector(run) forControlEvents:UIControlEventTouchUpInside];

    UIButton *sileo = [UIButton buttonWithType:UIButtonTypeSystem];
    sileo.translatesAutoresizingMaskIntoConstraints = NO;
    sileo.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    [sileo setTitle:@"Sileo" forState:UIControlStateNormal];
    [sileo setTitleColor:INFO() forState:UIControlStateNormal];
    sileo.backgroundColor = CARD(); sileo.layer.cornerRadius = 10;
    sileo.layer.borderColor = HAIR().CGColor; sileo.layer.borderWidth = 0.5;
    sileo.tag = 1001;
    [sileo addTarget:self action:@selector(installer:) forControlEvents:UIControlEventTouchUpInside];

    UIButton *term = [UIButton buttonWithType:UIButtonTypeSystem];
    term.translatesAutoresizingMaskIntoConstraints = NO;
    term.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    [term setTitle:@"Terminal" forState:UIControlStateNormal];
    [term setTitleColor:TEXT() forState:UIControlStateNormal];
    term.backgroundColor = CARD(); term.layer.cornerRadius = 10;
    term.layer.borderColor = HAIR().CGColor; term.layer.borderWidth = 0.5;
    term.tag = 1002;
    [term addTarget:self action:@selector(installer:) forControlEvents:UIControlEventTouchUpInside];

    g_status = [UILabel new]; g_status.translatesAutoresizingMaskIntoConstraints = NO;
    g_status.font = [UIFont systemFontOfSize:10]; g_status.textColor = SUB();
    g_status.textAlignment = NSTextAlignmentCenter;
    g_status.text = @"checking root...";

    g_log = [UITextView new]; g_log.translatesAutoresizingMaskIntoConstraints = NO;
    g_log.backgroundColor = [UIColor blackColor]; g_log.textColor = ACCENT();
    g_log.font = [UIFont fontWithName:@"Menlo" size:9.5]; g_log.editable = NO;
    g_log.textContainerInset = UIEdgeInsetsMake(6, 8, 6, 8);
    g_log.layer.cornerRadius = 10; g_log.layer.borderColor = HAIR().CGColor; g_log.layer.borderWidth = 0.5;
    g_log.text = @"";

    [vc.view addSubview:self.titleLabel]; [vc.view addSubview:self.subtitleLabel];
    [vc.view addSubview:g_rootPill]; [vc.view addSubview:div];
    [vc.view addSubview:self.table]; [vc.view addSubview:self.allButton];
    [vc.view addSubview:self.runButton]; [vc.view addSubview:sileo];
    [vc.view addSubview:term]; [vc.view addSubview:g_status]; [vc.view addSubview:g_log];

    [NSLayoutConstraint activateConstraints:@[
        [self.titleLabel.topAnchor constraintEqualToAnchor:g.topAnchor constant:6],
        [self.titleLabel.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [self.subtitleLabel.topAnchor constraintEqualToAnchor:self.titleLabel.bottomAnchor constant:1],
        [self.subtitleLabel.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [g_rootPill.centerYAnchor constraintEqualToAnchor:self.titleLabel.centerYAnchor],
        [g_rootPill.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [g_rootPill.widthAnchor constraintEqualToConstant:96], [g_rootPill.heightAnchor constraintEqualToConstant:26],
        [div.topAnchor constraintEqualToAnchor:self.subtitleLabel.bottomAnchor constant:8],
        [div.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [div.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [div.heightAnchor constraintEqualToConstant:0.5],
        [self.table.topAnchor constraintEqualToAnchor:div.bottomAnchor constant:6],
        [self.table.leadingAnchor constraintEqualToAnchor:g.leadingAnchor],
        [self.table.trailingAnchor constraintEqualToAnchor:g.trailingAnchor],
        [self.table.heightAnchor constraintEqualToConstant:252],
        [self.allButton.topAnchor constraintEqualToAnchor:self.table.bottomAnchor constant:7],
        [self.allButton.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [self.allButton.heightAnchor constraintEqualToConstant:36], [self.allButton.widthAnchor constraintEqualToConstant:52],
        [self.runButton.topAnchor constraintEqualToAnchor:self.table.bottomAnchor constant:7],
        [self.runButton.leadingAnchor constraintEqualToAnchor:self.allButton.trailingAnchor constant:6],
        [self.runButton.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [self.runButton.heightAnchor constraintEqualToConstant:36],
        [sileo.topAnchor constraintEqualToAnchor:self.runButton.bottomAnchor constant:7],
        [sileo.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [sileo.trailingAnchor constraintEqualToAnchor:vc.view.centerXAnchor constant:-3],
        [sileo.heightAnchor constraintEqualToConstant:36],
        [term.topAnchor constraintEqualToAnchor:sileo.topAnchor],
        [term.leadingAnchor constraintEqualToAnchor:vc.view.centerXAnchor constant:3],
        [term.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [term.heightAnchor constraintEqualToConstant:36],
        [g_status.topAnchor constraintEqualToAnchor:sileo.bottomAnchor constant:5],
        [g_status.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [g_status.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [g_log.topAnchor constraintEqualToAnchor:g_status.bottomAnchor constant:5],
        [g_log.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [g_log.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [g_log.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-6],
    ]];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    self.modules = [NSMutableArray array];

    [self.modules addObject:@{@"name":@"worse_query container escape", @"desc":@"PUBLIC, unpatched on 26.0-26.7.2: read/write every app container", @"status":@"PUBLIC", @"block":[^{ return RunRootPath(@"worse_query container escape") ?: RunModule(@"worse_query container escape"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"bl_sbx: itunesstored", @"desc":@"PUBLIC: arbitrary write as uid 501, MobileGestalt cache", @"status":@"PUBLIC", @"block":[^{ return RunRootPath(@"bl_sbx: itunesstored") ?: RunModule(@"bl_sbx: itunesstored"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"Sandbox: bad_query escape", @"desc":@"PROVEN: READ grants on /System and /usr/lib", @"status":@"PROVEN", @"block":[^{ return RunRootPath(@"Sandbox: bad_query escape") ?: RunModule(@"Sandbox: bad_query escape"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"Root-owned file read", @"desc":@"PROVEN: SystemVersion, Keychains, master.passwd", @"status":@"PROVEN", @"block":[^{ return RunRootPath(@"Root-owned file read") ?: RunModule(@"Root-owned file read"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"task_for_pid root sweep", @"desc":@"task port of a root pid -> its memory, its code, its identity", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"task_for_pid root sweep") ?: RunModule(@"task_for_pid root sweep"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"mach_vm R/W primitives", @"desc":@"the read/write step a task port unlocks", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"mach_vm R/W primitives") ?: RunModule(@"mach_vm R/W primitives"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"setuid-root binary scan", @"desc":@"setuid helpers reachable through the escape", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"setuid-root binary scan") ?: RunModule(@"setuid-root binary scan"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOKit reachable classes", @"desc":@"user clients an app can open = kernel attack surface", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"IOKit reachable classes") ?: RunModule(@"IOKit reachable classes"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"daemon surface: Mach services", @"desc":@"privileged daemons answering from the container", @"status":@"PIVOT", @"block":[^{ return RunRootPath(@"daemon surface: Mach services") ?: RunModule(@"daemon surface: Mach services"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"daemon pivot: writable paths", @"desc":@"paths a root daemon reads that we can write", @"status":@"PIVOT", @"block":[^{ return RunRootPath(@"daemon pivot: writable paths") ?: RunModule(@"daemon pivot: writable paths"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"daemon pivot: container write", @"desc":@"our writes landing in other containers", @"status":@"PIVOT", @"block":[^{ return RunRootPath(@"daemon pivot: container write") ?: RunModule(@"daemon pivot: container write"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"WebKit DFG UAF", @"desc":@"PROVEN: addrof + fakeobj (CVE-2025-43529)", @"status":@"PROVEN", @"block":[^{ return RunRootPath(@"WebKit DFG UAF") ?: RunModule(@"WebKit DFG UAF"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"JSC structure-ID scan", @"desc":@"the missing piece: in-object R/W without PAC", @"status":@"JSC", @"block":[^{ return RunRootPath(@"JSC structure-ID scan") ?: RunModule(@"JSC structure-ID scan"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"JSC fake-object R/W", @"desc":@"arbitrary read/write through a real structure ID", @"status":@"JSC", @"block":[^{ return RunRootPath(@"JSC fake-object R/W") ?: RunModule(@"JSC fake-object R/W"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"dyld PAC oracle", @"desc":@"PROVEN: dyld writes a resolved pointer into our slot", @"status":@"PROVEN", @"block":[^{ return RunRootPath(@"dyld PAC oracle") ?: RunModule(@"dyld PAC oracle"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"Kernel posture", @"desc":@"bootargs, AMFI, CSR, tfp0, unrestrictfs", @"status":@"LIVE", @"block":[^{ return RunRootPath(@"Kernel posture") ?: RunModule(@"Kernel posture"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOHID float->int sites", @"desc":@"73 conversion sites - user client gated today", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"IOHID float->int sites") ?: RunModule(@"IOHID float->int sites"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOSurface format-class", @"desc":@"format consistency, locked=7 / mismatch=0", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"IOSurface format-class") ?: RunModule(@"IOSurface format-class"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"AVE2 user client", @"desc":@"IOServiceOpen 0xe00002e2 - gated by the sandbox", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"AVE2 user client") ?: RunModule(@"AVE2 user client"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOSurfaceRoot selectors", @"desc":@"externalMethod sweep on a reachable root client", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"IOSurfaceRoot selectors") ?: RunModule(@"IOSurfaceRoot selectors"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"GPU / WebGL", @"desc":@"WebKit WebGL, PBO validation correct (ANGLE absent)", @"status":@"GPU", @"block":[^{ return RunRootPath(@"GPU / WebGL") ?: RunModule(@"GPU / WebGL"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOSkywalk varint (LAN)", @"desc":@"off-by-one in the parser - needs a LAN frame", @"status":@"LAN", @"block":[^{ return RunRootPath(@"IOSkywalk varint (LAN)") ?: RunModule(@"IOSkywalk varint (LAN)"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"XNU ND6 options (LAN)", @"desc":@"4 missing checks - needs a LAN frame", @"status":@"LAN", @"block":[^{ return RunRootPath(@"XNU ND6 options (LAN)") ?: RunModule(@"XNU ND6 options (LAN)"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"CoreServices path handling", @"desc":@"CVE-2026-20615: app -> root, unpatched on 26.2b1", @"status":@"ROOT2K", @"block":[^{ return RunRootPath(@"CoreServices path handling") ?: RunModule(@"CoreServices path handling"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"CoreServices race", @"desc":@"CVE-2026-20617: app -> root, unpatched on 26.2b1", @"status":@"ROOT2K", @"block":[^{ return RunRootPath(@"CoreServices path handling") ?: RunModule(@"CoreServices path handling"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"libxpc sandbox break", @"desc":@"CVE-2026-20667: app -> sandbox escape, unpatched on 26.2b1", @"status":@"SBX2K", @"block":[^{ return RunRootPath(@"CoreServices path handling") ?: RunModule(@"CoreServices path handling"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"cfprefsd confused deputy", @"desc":@"root daemon reachable from the container (CVE-2019-7286 class)", @"status":@"PIVOT", @"block":[^{ return RunRootPath(@"CoreServices path handling") ?: RunModule(@"CoreServices path handling"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"MobileGestalt cache poison", @"desc":@"SystemGroup write -> plist read process-wide", @"status":@"PIVOT", @"block":[^{ return RunRootPath(@"CoreServices path handling") ?: RunModule(@"CoreServices path handling"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"writetosymlinked", @"desc":@"PUBLIC: write anywhere under /var/mobile/Containers (fixed 26.2b2)", @"status":@"PUBLIC", @"block":[^{ return RunRootPath(@"CoreServices path handling") ?: RunModule(@"CoreServices path handling"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"dyld PAC oracle -> signPointer", @"desc":@"CVE-2026-20700: signPointer/context control -> signed gadgets", @"status":@"PROVEN", @"block":[^{ return RunRootPath(@"dyld PAC oracle") ?: RunModule(@"dyld PAC oracle"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"HFS flag-nibble", @"desc":@"5/5 on 26.2b1 vs 0/5 on 26.6", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"HFS flag-nibble") ?: RunModule(@"HFS flag-nibble"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"GPU process carrier", @"desc":@"offscreen GL surface as the GPU-process entry", @"status":@"GPU", @"block":[^{ return RunRootPath(@"GPU process carrier") ?: RunModule(@"GPU process carrier"); } copy], @"auto":@(NO)}];


    self.selected = [NSMutableIndexSet indexSet];   // nothing preselected

    AvePost([NSString stringWithFormat:@"launched modules=%lu", (unsigned long)self.modules.count]);
    AveLog(@"[*] RootSuite ready: tap a module to select it, then Run.");
    AveLog(@"[*] Sileo / Term    root.");
    refreshRootPill();
    [self updateRunTitle];

    // ---- autonomous mode: AUTO=<module name> runs that module at startup -----
    // Lets the host drive the app without touching the phone:
    //   pymobiledevice3 developer dvt launch <bid> --env AUTO=worse_query
    const char *autoEnv = getenv("AUTO");
    if (autoEnv && *autoEnv) {
        NSString *want = [NSString stringWithUTF8String:autoEnv];
        AveLog([NSString stringWithFormat:@"[*] AUTO mode: %@", want]);
        AvePost([NSString stringWithFormat:@"AUTO %@", want]);
        if ([want isEqualToString:@"ROOT"]) {
            BOOL have = RootProbe();
            AveLog(have ? @"[***] ROOT IS PRESENT: uid=0 confirmed" : @"[-] no root: uid!=0 everywhere");
            AvePost([NSString stringWithFormat:@"AUTOROOT %@", have ? @"YES" : @"NO"]);
            return YES;
        }
        for (NSUInteger i = 0; i < self.modules.count; i++) {
            NSString *nm = self.modules[i][@"name"];
            if ([nm rangeOfString:want].location != NSNotFound) {
                [self.selected addIndex:i];
                AveLog([NSString stringWithFormat:@"[*] auto-selected %@", nm]);
                break;
            }
        }
        if (self.selected.count) {
            [self.table reloadData];
            [self updateRunTitle];
            [self run];
        } else {
            AveLog(@"[!] AUTO: module not found");
        }
    }
    return YES;
}

- (void)updateRunTitle {
    [self.runButton setTitle:[NSString stringWithFormat:@">   (%lu)",
                              (unsigned long)self.selected.count] forState:UIControlStateNormal];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s { return self.modules.count; }

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    ModuleCell *c = [tv dequeueReusableCellWithIdentifier:@"c" forIndexPath:ip];
    [c configure:self.modules[ip.row] selected:[self.selected containsIndex:ip.row]];
    return c;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    if ([self.selected containsIndex:ip.row]) [self.selected removeIndex:ip.row];
    else [self.selected addIndex:ip.row];
    [self.table reloadData]; [self updateRunTitle];
    AveLog([NSString stringWithFormat:@"[*] %@ %@",
            [self.selected containsIndex:ip.row] ? @"selected" : @"cleared", self.modules[ip.row][@"name"]]);
}

- (void)toggleAll {
    if (self.selected.count == self.modules.count) [self.selected removeAllIndexes];
    else [self.selected addIndexesInRange:NSMakeRange(0, self.modules.count)];
    [self.table reloadData]; [self updateRunTitle];
    AveLog([NSString stringWithFormat:@"[*] selected count %lu", (unsigned long)self.selected.count]);
}

// MARK: installers (Sileo / Terminal)
- (void)installer:(UIButton *)b {
    if (self.running) return;
    self.running = YES; b.enabled = NO;
    NSString *which = (b.tag == 1001) ? @"Sileo" : @"Terminal";
    AveLog([NSString stringWithFormat:@"\n : %@", which]);
    AvePost([NSString stringWithFormat:@"INSTALL %@", which]);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *v = (b.tag == 1001) ? InstallSileo() : InstallTerminal();
        AveLog([NSString stringWithFormat:@"    %@", v]);
        AvePost([NSString stringWithFormat:@"INSTALLVERDICT %@ => %@", which, v]);
        refreshRootPill();
        dispatch_async(dispatch_get_main_queue(), ^{ self.running = NO; b.enabled = YES; });
    });
}

// MARK: run
- (void)run {
    if (self.running) return;
    if (self.selected.count == 0) { AveLog(@"[!] nothing selected"); return; }
    self.running = YES; self.runButton.enabled = NO;
    [self.runButton setTitle:@"running..." forState:UIControlStateNormal];
    AveLog([NSString stringWithFormat:@"\n=== RUN: %lu  ===", (unsigned long)self.selected.count]);
    AvePost([NSString stringWithFormat:@"RUN n=%lu", (unsigned long)self.selected.count]);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        [self.selected enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL *stop) {
            NSDictionary *m = self.modules[idx];
            AveLog([NSString stringWithFormat:@"\n %@ [%@]", m[@"name"], m[@"status"]]);
            AveSetStatus(@"working...");
            AvePost([NSString stringWithFormat:@"MOD %@", m[@"name"]]);
            CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
            NSString *v = ((ExploitBlock)m[@"block"])();
            double ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000.0;
            AveLog([NSString stringWithFormat:@"    %@   (%.0f )", v ?: @"( )", ms]);
            AvePost([NSString stringWithFormat:@"VERDICT %@ => %@", m[@"name"], v ?: @"nil"]);
        }];
        refreshRootPill();
        dispatch_async(dispatch_get_main_queue(), ^{
            AveLog(@"=== DONE ===");
            AvePost(@"RUN done");
            self.running = NO; self.runButton.enabled = YES;
            [self updateRunTitle];
        });
    });
}
@end
