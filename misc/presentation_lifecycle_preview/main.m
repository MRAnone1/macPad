#import <UIKit/UIKit.h>
#import <MetalKit/MetalKit.h>
#import <os/log.h>
#import <sys/utsname.h>
#import <TargetConditionals.h>
#include <math.h>
#include <string.h>

static NSDictionary *Event(NSString *name, NSString *run, NSUInteger frame, NSDictionary *fields) {
    NSMutableDictionary *value = [@{ @"event": name, @"run": run ?: @"",
        @"frame": @(frame), @"wall_seconds": @([NSDate date].timeIntervalSince1970),
        @"uptime_seconds": @([NSProcessInfo processInfo].systemUptime) } mutableCopy];
    [value addEntriesFromDictionary:fields ?: @{}];
    return value;
}

@interface FrameObservation : NSObject
@property(nonatomic, copy) NSString *run;
@property(nonatomic) NSUInteger number;
@property(nonatomic) BOOL gpuCompleted;
@property(nonatomic) BOOL presented;
@property(nonatomic) BOOL observed;
@property(nonatomic) BOOL humanConfirmed;
@end
@implementation FrameObservation
@end

@interface PaletteView : UIView
@property(nonatomic, copy) void (^didDraw)(void);
@end
@implementation PaletteView
- (void)drawRect:(CGRect)rect {
    CGContextRef context = UIGraphicsGetCurrentContext();
    if (!context) return;
    CGFloat halfWidth = self.bounds.size.width / 2;
    CGFloat halfHeight = self.bounds.size.height / 2;
    NSArray<UIColor *> *colors = @[UIColor.redColor, UIColor.greenColor, UIColor.blueColor, UIColor.yellowColor];
    for (NSUInteger index = 0; index < colors.count; index++) {
        CGContextSetFillColorWithColor(context, colors[index].CGColor);
        CGContextFillRect(context, CGRectMake((index % 2) * halfWidth, (index / 2) * halfHeight,
                                              halfWidth, halfHeight));
    }
    if (self.didDraw) self.didDraw();
}
@end

@interface PreviewController : UIViewController <MTKViewDelegate>
@property(nonatomic, strong) UISegmentedControl *mode;
@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, strong) UIButton *startButton;
@property(nonatomic, strong) UIButton *visibleButton;
@property(nonatomic, strong) UIView *stage;
@property(nonatomic, strong) PaletteView *palette;
@property(nonatomic, strong) MTKView *metalView;
@property(nonatomic, strong) id<MTLCommandQueue> queue;
@property(nonatomic, strong) id<MTLRenderPipelineState> pipeline;
@property(nonatomic, copy) NSString *metalError;
@property(nonatomic, strong) NSMutableArray<NSDictionary *> *events;
@property(nonatomic, copy) NSString *run;
@property(nonatomic, strong) FrameObservation *frame;
@property(nonatomic) BOOL started;
@property(nonatomic) BOOL finished;
@property(nonatomic) BOOL backgroundSeen;
@property(nonatomic) BOOL drawRequested;
@property(nonatomic) NSUInteger droppedEvents;
@property(nonatomic, copy) NSString *outcome;
@end

@implementation PreviewController
- (void)viewDidLoad {
    [super viewDidLoad];
    self.events = [NSMutableArray array];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    self.title = @"Presentation comparison";
    UILabel *instructions = [UILabel new];
    instructions.numberOfLines = 0;
    instructions.text = @"Choose UIKit or Metal and start. Confirm the four colors. Open Home, return once, then confirm again and share the report.";
    self.mode = [[UISegmentedControl alloc] initWithItems:@[@"UIKit", @"Metal"]];
    self.mode.selectedSegmentIndex = 0;
    self.mode.accessibilityIdentifier = @"presentationMode";
    [self.mode addTarget:self action:@selector(modeChanged) forControlEvents:UIControlEventValueChanged];
    self.statusLabel = [UILabel new];
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.text = @"Ready. One two-frame run per app launch.";
    self.statusLabel.accessibilityIdentifier = @"runStatus";
    self.startButton = [self button:@"Start" action:@selector(startRun)];
    self.startButton.accessibilityIdentifier = @"startRun";
    self.visibleButton = [self button:@"Four colors visible" action:@selector(confirmVisible)];
    self.visibleButton.enabled = NO;
    UIButton *stop = [self button:@"Stop" action:@selector(stopRun)];
    UIButton *share = [self button:@"Share report" action:@selector(shareReport:)];
    self.stage = [UIView new];
    self.stage.backgroundColor = UIColor.blackColor;
    self.palette = [PaletteView new];
    self.palette.translatesAutoresizingMaskIntoConstraints = NO;
    self.palette.contentMode = UIViewContentModeRedraw;
    self.palette.isAccessibilityElement = YES;
    self.palette.accessibilityLabel = @"Four color UIKit fixture";
    [self.stage addSubview:self.palette];
    [NSLayoutConstraint activateConstraints:@[
        [self.palette.leadingAnchor constraintEqualToAnchor:self.stage.leadingAnchor],
        [self.palette.trailingAnchor constraintEqualToAnchor:self.stage.trailingAnchor],
        [self.palette.topAnchor constraintEqualToAnchor:self.stage.topAnchor],
        [self.palette.bottomAnchor constraintEqualToAnchor:self.stage.bottomAnchor]]];
    UIStackView *buttons = [[UIStackView alloc] initWithArrangedSubviews:@[self.startButton, stop, share]];
    buttons.distribution = UIStackViewDistributionFillEqually;
    buttons.spacing = 12;
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[instructions, self.mode, self.stage,
                                                                       self.statusLabel, self.visibleButton, buttons]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 14;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.leadingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.leadingAnchor constant:20],
        [stack.trailingAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.trailingAnchor constant:-20],
        [stack.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:16],
        [stack.bottomAnchor constraintLessThanOrEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-16],
        [self.stage.heightAnchor constraintEqualToConstant:240]]];
    __weak PreviewController *weakSelf = self;
    self.palette.didDraw = ^{ [weakSelf paletteDrawn]; };
    NSNotificationCenter *center = NSNotificationCenter.defaultCenter;
    for (NSNotificationName name in @[UIApplicationWillResignActiveNotification,
                                     UIApplicationDidEnterBackgroundNotification,
                                     UIApplicationWillEnterForegroundNotification,
                                     UIApplicationDidBecomeActiveNotification]) {
        [center addObserver:self selector:@selector(lifecycle:) name:name object:nil];
    }
    struct utsname system;
    NSString *machine = uname(&system) == 0 ? [NSString stringWithUTF8String:system.machine] : @"unknown";
    [self record:Event(@"app_ready", nil, 0, @{
        @"machine": machine, @"os": UIDevice.currentDevice.systemVersion,
        @"os_build": NSProcessInfo.processInfo.operatingSystemVersionString,
        @"bundle_version": [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleVersion"] ?: @"",
        @"target": TARGET_OS_SIMULATOR ? @"simulator" : @"device",
        @"presentation_callback_supported": @(!TARGET_OS_SIMULATOR) })];
}

- (UIButton *)button:(NSString *)title action:(SEL)action {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    [button setTitle:title forState:UIControlStateNormal];
    [button addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    return button;
}

- (void)record:(NSDictionary *)event {
    NSAssert(NSThread.isMainThread, @"UI event recording runs on the main thread");
    if (self.events.count < 256) {
        [self.events addObject:event];
        os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_INFO, "Presentation comparison %{public}@ frame %{public}@ run %{public}@",
                         event[@"event"], event[@"frame"], event[@"run"]);
    } else {
        self.droppedEvents += 1;
        os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_INFO, "PresentationCompare %{public}@ run=%{public}@ frame=%{public}@",
                         event[@"event"], event[@"run"], event[@"frame"]);
    }
}

- (void)prepareMetal {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) { self.metalError = @"Metal device unavailable"; return; }
    self.metalView = [[MTKView alloc] initWithFrame:CGRectZero device:device];
    self.metalView.translatesAutoresizingMaskIntoConstraints = NO;
    self.metalView.paused = YES;
    self.metalView.enableSetNeedsDisplay = NO;
    self.metalView.framebufferOnly = NO;
    ((CAMetalLayer *)self.metalView.layer).allowsNextDrawableTimeout = YES;
    self.metalView.colorPixelFormat = MTLPixelFormatBGRA8Unorm;
    self.metalView.delegate = self;
    self.metalView.hidden = YES;
    self.metalView.isAccessibilityElement = YES;
    self.metalView.accessibilityLabel = @"Four color Metal fixture";
    [self.stage addSubview:self.metalView];
    [NSLayoutConstraint activateConstraints:@[
        [self.metalView.leadingAnchor constraintEqualToAnchor:self.stage.leadingAnchor],
        [self.metalView.trailingAnchor constraintEqualToAnchor:self.stage.trailingAnchor],
        [self.metalView.topAnchor constraintEqualToAnchor:self.stage.topAnchor],
        [self.metalView.bottomAnchor constraintEqualToAnchor:self.stage.bottomAnchor]]];
    self.queue = [device newCommandQueue];
    NSString *source = @"#include <metal_stdlib>\nusing namespace metal;\n"
        "vertex float4 palette_vertex(uint i [[vertex_id]]) { float2 p[3] = {float2(-1,-1),float2(3,-1),float2(-1,3)}; return float4(p[i],0,1); }\n"
        "fragment float4 palette_fragment(float4 p [[position]], constant float2 &size [[buffer(0)]]) { bool left = p.x < size.x/2; bool top = p.y < size.y/2; if(top) return left ? float4(1,0,0,1) : float4(0,1,0,1); return left ? float4(0,0,1,1) : float4(1,1,0,1); }\n";
    NSError *error = nil;
    id<MTLLibrary> library = [device newLibraryWithSource:source options:nil error:&error];
    MTLRenderPipelineDescriptor *descriptor = [MTLRenderPipelineDescriptor new];
    descriptor.vertexFunction = [library newFunctionWithName:@"palette_vertex"];
    descriptor.fragmentFunction = [library newFunctionWithName:@"palette_fragment"];
    descriptor.colorAttachments[0].pixelFormat = self.metalView.colorPixelFormat;
    if (descriptor.vertexFunction && descriptor.fragmentFunction) {
        self.pipeline = [device newRenderPipelineStateWithDescriptor:descriptor error:&error];
    }
    if (!self.queue || !self.pipeline) self.metalError = error.localizedDescription ?: @"Metal setup failed";
}

- (void)modeChanged {
    self.palette.hidden = self.mode.selectedSegmentIndex == 1;
    self.metalView.hidden = !self.palette.hidden;
}

- (void)startRun {
    if (self.started || UIApplication.sharedApplication.applicationState != UIApplicationStateActive) return;
    self.started = YES;
    self.mode.enabled = NO;
    self.startButton.enabled = NO;
    self.run = NSUUID.UUID.UUIDString;
    self.outcome = @"running";
    [self record:Event(@"run_started", self.run, 0, @{
        @"mode": self.mode.selectedSegmentIndex == 0 ? @"UIKit" : @"Metal",
        @"thermal": @(NSProcessInfo.processInfo.thermalState),
        @"low_power": @(NSProcessInfo.processInfo.lowPowerModeEnabled) })];
    if (self.mode.selectedSegmentIndex == 1) {
        [self record:Event(@"metal_setup_started", self.run, 0, @{})];
        [self prepareMetal];
        [self modeChanged];
        [self.stage layoutIfNeeded];
        [self record:Event(@"metal_setup_finished", self.run, 0,
                           @{@"pipeline_ready": @(self.pipeline != nil), @"error": self.metalError ?: @""})];
    }
    [self requestFrame:1];
}

- (void)requestFrame:(NSUInteger)number {
    if (self.finished || number > 2 || UIApplication.sharedApplication.applicationState != UIApplicationStateActive) return;
    self.frame = [FrameObservation new];
    self.frame.run = self.run;
    self.frame.number = number;
    self.visibleButton.enabled = NO;
    self.drawRequested = YES;
    self.statusLabel.text = [NSString stringWithFormat:@"Waiting for frame %lu…", (unsigned long)number];
    [self record:Event(@"frame_requested", self.run, number, @{})];
    if (self.mode.selectedSegmentIndex == 0) {
        [self.palette setNeedsDisplay];
    } else if (self.pipeline) {
        [self.metalView draw];
    } else {
        [self fail:self.metalError ?: @"Metal setup unavailable"];
    }
}

- (void)paletteDrawn {
    if (!self.drawRequested || self.finished || self.mode.selectedSegmentIndex != 0) return;
    self.drawRequested = NO;
    [self record:Event(@"uikit_draw", self.run, self.frame.number, @{})];
    [self frameObserved:self.frame];
}

- (void)frameObserved:(FrameObservation *)frame {
    if (self.finished || self.frame != frame || frame.observed) return;
    frame.observed = YES;
    self.visibleButton.enabled = YES;
    self.statusLabel.text = frame.number == 1 ? @"Confirm the colors, open Home, then return once." :
        @"Two frames recorded. Confirm the colors and share the report.";
}

- (void)confirmVisible {
    if (!self.frame.observed || !self.visibleButton.enabled) return;
    [self record:Event(@"human_colors_visible", self.run, self.frame.number, @{})];
    self.frame.humanConfirmed = YES;
    self.visibleButton.enabled = NO;
    if (self.frame.number == 2) {
        self.finished = YES;
        self.outcome = @"two_frames_observed_and_confirmed";
        self.statusLabel.text = @"Two frames and both lifecycle observations are available for review.";
    }
}

- (void)lifecycle:(NSNotification *)notification {
    [self record:Event(notification.name, self.run, self.frame.number, @{
        @"application_state": @(UIApplication.sharedApplication.applicationState) })];
    if (!self.started || self.finished) return;
    if ([notification.name isEqualToString:UIApplicationWillResignActiveNotification]) {
        if (!self.frame.observed) [self fail:@"Application became inactive before frame observation completed"];
    } else if ([notification.name isEqualToString:UIApplicationDidEnterBackgroundNotification]) {
        if (!self.frame.humanConfirmed) {
            [self fail:@"Colors were not confirmed before entering the background"];
            return;
        }
        self.backgroundSeen = YES;
    } else if ([notification.name isEqualToString:UIApplicationDidBecomeActiveNotification] && self.backgroundSeen) {
        self.backgroundSeen = NO;
        if (self.frame.number == 1 && self.frame.observed) [self requestFrame:2];
    }
}

- (void)fail:(NSString *)message {
    if (self.finished) return;
    [self record:Event(@"run_failed", self.run, self.frame.number, @{@"reason": message})];
    self.finished = YES;
    self.outcome = @"failed_or_stopped";
    self.drawRequested = NO;
    self.visibleButton.enabled = NO;
    self.statusLabel.text = message;
}

- (void)stopRun {
    if (self.started && !self.finished) [self fail:@"Stopped by user"];
}

- (void)drawInMTKView:(MTKView *)view {
    if (!self.drawRequested || self.finished || self.frame.number > 2) return;
    self.drawRequested = NO;
    FrameObservation *frame = self.frame;
    id<CAMetalDrawable> drawable = view.currentDrawable;
    MTLRenderPassDescriptor *pass = view.currentRenderPassDescriptor;
    id<MTLCommandBuffer> command = [self.queue commandBuffer];
    id<MTLBuffer> samples = [view.device newBufferWithLength:1024 options:MTLResourceStorageModeShared];
    if (!drawable || !pass || !command || !samples || drawable.texture.width < 4 || drawable.texture.height < 4) {
        [self fail:@"Drawable or command resources unavailable"];
        return;
    }
    memset(samples.contents, 0x5a, 1024);
    id<MTLRenderCommandEncoder> encoder = [command renderCommandEncoderWithDescriptor:pass];
    if (!encoder) { [self fail:@"Render encoder unavailable"]; return; }
    [encoder setRenderPipelineState:self.pipeline];
    float size[2] = {(float)drawable.texture.width, (float)drawable.texture.height};
    [encoder setFragmentBytes:size length:sizeof(size) atIndex:0];
    [encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
    [encoder endEncoding];
    id<MTLBlitCommandEncoder> blit = [command blitCommandEncoder];
    if (!blit) { [self fail:@"Readback encoder unavailable"]; return; }
    for (NSUInteger index = 0; index < 4; index++) {
        NSUInteger x = drawable.texture.width * (index % 2 ? 3 : 1) / 4;
        NSUInteger y = drawable.texture.height * (index / 2 ? 3 : 1) / 4;
        [blit copyFromTexture:drawable.texture sourceSlice:0 sourceLevel:0
                sourceOrigin:MTLOriginMake(x, y, 0) sourceSize:MTLSizeMake(1, 1, 1)
                    toBuffer:samples destinationOffset:index * 256 destinationBytesPerRow:256 destinationBytesPerImage:256];
    }
    [blit endEncoding];
    __weak PreviewController *weakSelf = self;
#if !TARGET_OS_SIMULATOR
    [drawable addPresentedHandler:^(id<MTLDrawable> presented) {
        // Read drawable properties while the callback owns the valid argument.
        double presentedTime = presented.presentedTime;
        NSUInteger drawableID = presented.drawableID;
        NSDictionary *event = Event(@"drawable_presented", frame.run, frame.number, @{
            @"presented_time": isfinite(presentedTime) ? @(presentedTime) : NSNull.null,
            @"positive_presented_time": @(isfinite(presentedTime) && presentedTime > 0),
            @"drawable_id": @(drawableID) });
        dispatch_async(dispatch_get_main_queue(), ^{
            PreviewController *owner = weakSelf;
            if (!owner) return;
            [owner record:event];
            if (!owner.finished && owner.frame == frame) {
                if (!isfinite(presentedTime) || presentedTime <= 0) {
                    [owner fail:@"Presentation callback has no positive presentation timestamp"];
                    return;
                }
                frame.presented = YES;
                if (frame.gpuCompleted) [owner frameObserved:frame];
            }
        });
    }];
#else
    [self record:Event(@"presentation_callback_unavailable", frame.run, frame.number,
                       @{@"target": @"simulator"})];
#endif
    [command addCompletedHandler:^(id<MTLCommandBuffer> completed) {
        const uint8_t expected[4][4] = {{0,0,255,255}, {0,255,0,255}, {255,0,0,255}, {0,255,255,255}};
        BOOL pixelsMatch = completed.status == MTLCommandBufferStatusCompleted;
        NSMutableArray *pixels = [NSMutableArray array];
        for (NSUInteger index = 0; index < 4; index++) {
            const uint8_t *pixel = (const uint8_t *)samples.contents + index * 256;
            [pixels addObject:@[@(pixel[0]), @(pixel[1]), @(pixel[2]), @(pixel[3])]];
            pixelsMatch = pixelsMatch && memcmp(pixel, expected[index], 4) == 0;
        }
        NSDictionary *event = Event(@"command_completed", frame.run, frame.number, @{
            @"status": @(completed.status), @"error": completed.error.localizedDescription ?: @"",
            @"sample_bgra": pixels, @"four_samples_match": @(pixelsMatch) });
        dispatch_async(dispatch_get_main_queue(), ^{
            PreviewController *owner = weakSelf;
            if (!owner) return;
            [owner record:event];
            if (owner.finished || owner.frame != frame) return;
            if (!pixelsMatch) { [owner fail:@"GPU command or four pixel samples failed"]; return; }
            frame.gpuCompleted = YES;
#if TARGET_OS_SIMULATOR
            [owner frameObserved:frame];
#else
            if (frame.presented) [owner frameObserved:frame];
#endif
        });
    }];
    [self record:Event(@"command_commit", frame.run, frame.number, @{
        @"drawable_width": @(drawable.texture.width), @"drawable_height": @(drawable.texture.height) })];
    [command presentDrawable:drawable];
    [command commit];
}

- (void)mtkView:(MTKView *)view drawableSizeWillChange:(CGSize)size {
    [self record:Event(@"drawable_size_changed", self.run, self.frame.number,
                       @{@"width": @(size.width), @"height": @(size.height)})];
}

- (void)shareReport:(UIButton *)sender {
    NSDictionary *report = @{@"schema": @"macws.presentation-comparison.v1", @"events": [self.events copy],
        @"mode": self.mode.selectedSegmentIndex == 0 ? @"UIKit" : @"Metal",
        @"finished": @(self.finished), @"outcome": self.outcome ?: @"not_started",
        @"target": TARGET_OS_SIMULATOR ? @"simulator" : @"device",
        @"presentation_callback_supported": @(!TARGET_OS_SIMULATOR),
        @"dropped_events": @(self.droppedEvents), @"human_review_required": @YES};
    NSError *error = nil;
    NSData *data = [NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted error:&error];
    if (!data || data.length > 1024 * 1024) { self.statusLabel.text = @"Report could not be encoded"; return; }
    NSURL *file = [NSURL fileURLWithPath:[NSTemporaryDirectory() stringByAppendingPathComponent:@"PresentationComparison.json"]];
    if (![data writeToURL:file options:NSDataWritingAtomic error:&error]) {
        self.statusLabel.text = error.localizedDescription;
        return;
    }
    UIActivityViewController *activity = [[UIActivityViewController alloc] initWithActivityItems:@[file] applicationActivities:nil];
    activity.popoverPresentationController.sourceView = sender;
    activity.popoverPresentationController.sourceRect = sender.bounds;
    [self presentViewController:activity animated:YES completion:nil];
}

- (void)dealloc {
    [NSNotificationCenter.defaultCenter removeObserver:self];
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic, strong) UIWindow *window;
@end
@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [[UINavigationController alloc] initWithRootViewController:[PreviewController new]];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char **argv) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(AppDelegate.class));
    }
}
