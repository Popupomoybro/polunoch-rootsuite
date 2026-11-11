#import <UIKit/UIKit.h>

// ---------------------------------------------------------------------------
// RootSuite — all the paths to uid 0 in one app, selectable and runnable.
// UI is drawn in code (no storyboards, no assets): dark cards, status pills,
// one accent button.  nothing animated, no timers — cheap on battery/CPU.
// ---------------------------------------------------------------------------
@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UITableView *table;
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UILabel *titleLabel;
@property (nonatomic, strong) UILabel *subtitleLabel;
@property (nonatomic, strong) UIButton *allButton;
@property (nonatomic, strong) UIButton *runButton;
@property (nonatomic, strong) NSMutableArray *modules;      // NSDictionary per module
@property (nonatomic, strong) NSMutableIndexSet *selected;
@property (nonatomic, assign) BOOL running;
@end

typedef NSString * (^ExploitBlock)(void);

void AveLog(NSString *s);
void AvePost(NSString *s);
void AveSleep(int ms);
NSString *AveReadFile(NSString *path);
void AveSetStatus(NSString *s);
