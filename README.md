# SmartThings Edge ONVIF Driver
Supports motion detection and streaming from ONVIF-compliant IP cameras
## Pre-requisites
- SmartThings hub capable of running Edge platform
- SmartThings account
- SmartThings mobile app
- ONVIF-compliant IP camera supporting **Profile S** (Streaming) 
## Installation Steps
Use my shared projects Edge channel to complete these steps:
1. Enroll hub in my shared test driver Edge channel:  https://bestow-regional.api.smartthings.com/invite/Q1jP7BqnNNlL
2. Choose to install driver 'ONVIF Video Camera V1'

### Camera device discovery and SmartThings device creation
Once the driver is installed to your hub, use the SmartThings mobile app to initiate an Add device -> Scan nearby devices.  Your ONVIF-compliant IP cameras will be discovered and SmartThings devices added to the 'No room assigned' room OR the room where your SmartThings hub device is located.

Note:  If a camera cannot be discovered, it could be due to any of these reasons:
* you haven't enabled ONVIF or ONVIF discovery for the camera in the manufacturer's app
* it may not support ONVIF
* it is on a different subnet from your SmartThings hub
* it is behind a firewall/VPN.
* your camera is using an IP address that is not in the standard private IP address range

## Usage

Once the UserID and Password has been configured in device Settings, the Refresh button on the device Control screen should be tapped to establish connection to the camera and retrieve additional camera configuration data.  If successful, additional information will now be shown in the Info table, and the camera is now ready for streaming video (see below).

At this point, the user may choose to enable motion events by turning the Motion Events switch to ON.  If the motion events are successfully started, then the switch will remain in the ON position, and the Info Status field will be updated to 'Subscribed to events'.  If the switch reverts back to OFF position, this means that motion events are not available or an error occurred during motion event initialization.  At any time, motion events can be turned back OFF using the Motion Events switch.  The Info Status field will then be updated to 'Unsubscribed to events'.

### Video Streaming
Due to limitations in the SmartThings Edge platform, video is not available directly within the SmartThings device Controls screen.  Instead, a SmartThings Camera Group must be created and your ONVIF cameras added to it.  Then tapping on the Camera Group, live video will be displayed from the cameras.

### Motion Detection
The Edge driver subscribes to basic motion change events from the camera and these motion state changes can be used in creating Routines.  The Motion Events switch on the device Control screen must be in the ON position to receive events from the camera.

### Cameras without static IP addresses
Some cameras may occasionally change IP addresses if they are not assigned static IP addresses on your router.  If motion events are enabled for the SmartThings camera device OR if a Refresh is initiated, and the camera cannot be found at its known IP address, then the driver will automatically initiate a periodic re-discovery process until it finds the camera again and determines its new IP address.

## Device Settings

### Minimum motion-active interval
Use this setting to eliminate multiple rapid motion alerts.  This can be useful if you have routines triggered by motion events, and it also cuts down the number of state changes sent to SmartThings, as well as captured in device history.

Values can be any number of seconds up to 3,600 (one hour).  For example a value of 10 means allow only one motion active alert within a 10 second window.  A value of 0 effectively turns this option off.  Note that some cameras allow a similar configuration setting through the manufacturer app.

### Auto motion revert
Use this setting to force motion to inactive regardless of when/if the inactive event is received from the camera.

### Auto-revert delay
Use this setting when Auto motion revert is set to 'Auto-revert'.  

Value provided is the number of seconds to wait - after an active motion is received - to revert motion to inactive.

### Video Stream Selection
Use this setting to control which stream - main or sub - to use to view your camera.  After changing this value you **must** Refresh the device for it to take effect.  Note that 'main' is assumed to be the *first* video profile in the camera's response data, and 'sub' is assumed to be the *second* video profile in the camera's configuration data.

### Motion Rule Selection
Most Profile S cameras support the *RuleEngine/CellMotionDetector* rule for triggering motion events, so this is the default rule used by the driver.  However if you have a Profile T camera, you can alternatively use the *VideoSource/MotionAlarm* rule to activate SmartThings motion.  After changing this value you **must** Refresh the device for it to take effect.

### Event Subscription
For future use to select ONVIF subscription type.  Note that the current version of this driver supports the *WS-Basic Notifications* specification.  *Pull-Point Notifications* will be supported at a later date, which will address cases where cameras are behind a firewall or on another subnet.

### UserID and Password
This is the access credentials required to access your camera, initially set up in the camera manufacturer's app.  Note that some brands of cameras, such as Hikvision, require unique ONVIF credentials to be configured in the camera's application.  See Hikvision notes below.
- **Do not use camera passwords containing the characters '@' or '?'.**

## Device Controls screen
### Main section
- **Motion sensor**: state of motion (active/inactive)

- **Motion Events**: switch to turn on or off motion event processing

### Info section
- **Status**:  a text field showing the most recent status of the connection with the camera
- **Info**:  a table of values retrieved from the camera showing various camera configuration properties; The Info table can be especially useful to see (1) if your camera device is responding properly, and (2) identifying information about your camera such as IP address, manufacturer, name, profiles supported, etc.
- **Refresh**:  a button used to force a re-initialization with the camera

## Device History
All motion events, status changes, and device info table updates will be captured in history.

## Routine Triggers
The device's motion state (active/inactive) can be used in the IF condition of SmartThings automation routines.

## Current Limitations
- Video
  - Streaming is fairly limited to what the SmartThings mobile app currently allows.  At present, the only way to view video streams with this driver is to create a camera group and view the video streams through the group.  This by definition requires more than one camera to create a group.  I have a virtual camera device driver also available on my test channel, which you can use to create a camera group if you have only one IP camera.
  - The video stream displayed via a camera group **defaults to the camera's Substream**, which is typically a lower resolution (e.g. 360H x 640W or 480H x 640W) and commonly referred to as a preview stream. This was a conscious decision since SmartThings is unable to display multiple video streams at higher resolution.  Note that the user can choose to instead use a the main stream for higher resolution via device Settings.
  - Andriod users will benefit from some viewing options that are not available on iOS
  - Video streaming is only working when you are connected to your home network
- Motion
  - Motion events may not work if cameras are on a separate subnet or behind a firewall. Note that this will be addressed in a future driver update.
  - Two motion rules are supported:  *RuleEngine/CellMotionDetector* and *VideoSource/MotionAlarm*

## Notes on Security

Login Passwords are encrypted in all ONVIF messages between the hub and camera.  However there is one case where the password is transmitted on the network 'in the clear' and this unfortunately is a current limitation of the SmartThings platform.  When video streaming is activated to be viewed within the mobile app, the Edge driver is asked for the camera's RTSP streaming URL.  Currently, the only way to inform SmartThings of the UserID and Password is to provide them as part of the RTSP URL (in the form of rtsp://\<UserID\>:\<Password>@<StreamURL\>).  There is no option to provide the Password encrypted.

## Notes on Specific Camera Brands
The official list of camera models that have passed ONVIF certification can be found at this website:  https://www.onvif.org/conformant-products/.

Even if your camera is not listed there, check the manufacturer's documentation to see if they *claim* ONVIF compatibility.  It should be noted that although a manufacturer may claim ONVIF compliance, it may not be a complete, or fully-functional implementation if it is not on the official conformant product list noted above.  Notes on how this driver works with brand-specific cameras will be updated in this document as they are discovered.

#### Profiles
ONVIF defines specific Profiles, which define the feature set the camera supports.  This Edge driver requires only the Streaming Profile (Profile S) for both streaming video and *CellMotionDetector* events, but it can also support the *MotionAlarm* events from Profile T cameras.

### Reolink
Many Reolink cameras should work with this driver, but not all.

There are some anomolies in the Reolink ONVIF implementation (Reolink models are not offically conformant). For example, there is a bug in the event subscription renewal function where the camera does not set the proper subscription termination time.  However this particular issue should not cause any apparent problems to the user.

Other earlier camera models return an incorrect subscription reference address used for subscription renewal requests, however this known issue is accounted for in the driver code.  

(These issues expose themselves in the *ONVIF Device Manager* application, which is either unable to show events at all, or the event display stops working after a minute or so.)

Some of the more recent camera models have a settings option which must be enabled in via the Reolink ***desktop*** application.  (The setting is not found in the Reolink mobile app!)  Look for an **RTSP** setting under [Network/Advanced/Port](https://community.smartthings.com/t/st-edge-onvif-compliant-ip-camera-motion-detection-video-streaming-testers-wanted/242326/435?u=taustin) and enable it.  You should then see an ONVIF option which must also be turned on.

Confirmed to work: E1Pro, E1 Zoom PTZ Indoor Wi-Fi, C1Pro, RLC-410W, RLC-411S, RLC-411WS, RLC-422, RLC-510WA, RLC-520, RLC-820A, RLC-822A, RLC-823A

Confirmed *not* to work (cannot be discovered):  Model E1   

### Hikvision
- ONVIF must be enabled and a specific ONVIF UserID and Password defined with at least 'Media user' access level (Network->Advanced Settings->Integration Protocol)

- RTSP Authentication must be set to 'digest/basic' (System->Security->Authentication)

- Motion detection should be enabled (Event->Basic Event->Motion Detection)

- Video format must be H264 or H264+ for video streaming to work in the SmartThings mobile app.  Due to SmartThings limitations the maximum size for screen resolution is 1920 x 1080

- Notes regarding motion detection configuration through the Hikvision app:
  - Motion detection and line crossing events have multiple options and sensitivity settings. There is scope for many areas to be detected in any shape or form.  Line crossing can be set for both directions, left cross, right cross or entrance/exit - with sensitivity settings and a maximum of 4 different lines.  Setting your cameras incorrectly can cause repeated false alerts!

Confirmed to work:  DS-2CD2335FWD-I, DS-2DE4215IW, 2CD2185FWD-I and 2CD2185FWD-IS

### Interlogix
Confirmed to work: TVT-5301 and TVW-5302

### Annke
Confirmed to work:  ANNKE C800 4K PoE (Model designation: I91BF)

### Foscam
Confirmed to work: R2 V4

### Axis
Confirmed to work: 
- M1045-LW, M1065-LW,  M3044-WV
- M1004-W (video streaming only, no motion alerts)

### TP-Link TAPO
Confirmed to work: c100/200/300

### Duhua
Must disable authentication

### TRENDnet TV-IP321PI
Be sure that the video sub-stream is configured for H.264
