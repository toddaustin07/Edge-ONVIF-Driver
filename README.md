# SmartThings Edge ONVIF Driver
Supports motion detection and streaming from ONVIF-compliant IP cameras
## Pre-requisites
- SmartThings hub capable of running Edge platform
- SmartThings account
- SmartThings mobile app
- ONVIF-compliant IP camera supporting Profile S (Streaming) 
## Installation Steps
Use my shared projects Edge channel to complete these steps:
1. Enroll hub in my shared projects Edge channel
2. Choose to install driver 'ONVIF Video Camera V1'

### Camera device discovery and SmartThings device creation
Once the driver is installed to your hub, use the SmartThings mobile app to initiate an Add device -> Scan nearby devices.  Your ONVIF-compliant IP cameras will be discovered and SmartThings devices added to the 'No room assigned' room.

Note:  If a camera cannot be discovered, then it probably doesn't support ONVIF.

## Usage

Once the UserID and Password has been configured in device Settings, the Refresh button on the device Control screen should be tapped to establish connection to the camera and retrieve additional camera configuration data.  If successful, additional information will now be shown in the Info table, and the camera is now ready for streaming video (see below).

At this point, the user may choose to enable motion events by turning the Motion Events switch to ON.  If the motion events are successfully turned on, then the switch will remain in the ON position, and the Info Status field will be updated to 'Subscribed to events'.  If the switch reverts back to OFF position, this means that motion events are not available or an error occurred during motion event initialization.  At any time, motion events can be turned back OFF using the Motion Events switch.  The Info Status field will then be updated to 'Unsubscribed to events'.

### Video Streaming
Due to limitations in the SmartThings Edge platform, video is not available directly within the SmartThings device Controls screen.  Instead, a SmartThings Camera Group must be created and your ONVIF cameras added to it.  Then tapping on the Camera Group, live video will be displayed from the cameras.

### Motion Detection
The Edge driver subscribes to basic motion change events from the camera and these motion state changes can be used in creating Routines.  The Motion Events switch on the device Control screen must be in the ON position to receive events from the camera.

## Device Settings

### Minimum motion-active interval
Use this setting to eliminate multiple rapid motion alerts.  This can be useful if you have routines triggered by motion events, and it also cuts down the number of state changes sent to SmartThings, as well as captured in device history.

Values can be any number of seconds up to 3,600 (one hour).  For example a value of 10 means allow only one motion active alert within a 10 second window.  A value of 0 effectively turns this option off.  Note that some cameras allow a similar configuration setting through the manufacturer app.

### Auto motion revert
Use this setting to force motion to inactive regardless of when/if the inactive event is received from the camera.

### Auto-revert delay
Use this setting when Auto motion revert is set to 'Auto-revert'.  

Value provided is the number of seconds to wait - after an active motion is received - to revert motion to inactive.

### Event Subscription
For future use to select ONVIF subscription type to accommodate various camera capabilities

### UserID and Password
This is the access credentials required to access your camera, initially set up in the camera manufacturer's app

## Device Controls screen
### Main section
- **Motion sensor**: state of motion (active/inactive)

- **Motion Events**: switch to turn on or off motion event processing

### Info section
- **Status**:  a text field showing the most recent status of the connection with the camera
- **Info**:  a table of values retrieved from the camera showing various camera configuration properties
- **Refresh**:  a button used to force a re-initialization with the camera

## Device History
All motion events, streaming requests, status changes, and device data updates will be captured in history.  The Info table can be especially useful to see (1) if your camera device is responding properly, and (2) identifying information about your camera such as IP address, manufacturer, name, profiles, etc.

## Current Limitations
- Video
  - Streaming is fairly limited to what the SmartThings mobile app currently allows.  At present, the only way to view video streams with this driver is to create a camera group and view the video streams through via the group.  This by definition requires more than one camera to create a group.
  - The video stream displayed via a camera group is the camera's subtream, which is typically a low resolution (e.g. 360H x 640W or 480H x 640W). This was a conscious decision for now.  It is possible to use the main stream which is whatever resolution is configured by the camera and this may be made a configuration preference in a future driver
  - Andriod users will benefit from some viewing options that are not available on iOS
  - It appears that video through camera groups cannot be viewed when the mobile app is connected via cellular, so it is available only when connected to the home network
- Motion
  - Motion events may not work if cameras are on a separate subnet or behind a firewall. Note that this will be addressed in a future driver update.
  - Only generic motion alerts are supported

## Notes on Security
Login Passwords are encrypted in all ONVIF messages between the hub and camera.  However there is one case where the password is transmitted on the network 'in the clear' and this unfortunately is a current limitation of the SmartThings platform.  When video streaming is activated to be viewed within the mobile app, the Edge driver is asked for the camera's RTSP streaming URL.  Currently, the only way to inform SmartThings of the UserID and Password is to provide them as part of the RTSP URL (in the form of rtsp://\<UserID\>:\<Password>@<StreamURL\>).  There is no option to provide the Password encrypted.

## Notes on Specific Camera Brands
The official list of camera models that have passed ONVIF certification can be found at this website:  https://www.onvif.org/conformant-products/.

Even if your camera is not listed there, check the manufacturers documentation to see if they *claim* ONVIF compatibility.  It should be noted that although a manufacturer may claim ONVIF compliance, it may not be a complete, or fully-functional implementation if it is not on the official conformant product list noted above.  Notes on how this driver works with brand-specific cameras will be updated in this document as they are discovered.

To date, this driver has been tested with Reolink and Hikvision cameras.

#### Profiles
ONVIF defines specific Profiles, which define the feature set the camera supports.  This Edge driver requires only the Streaming Profile (Profile S).

### Reolink
Many Reolink cameras should work with this driver, but not all.

There are some anomolies in the Reolink ONVIF implementation (Reolink models are not offically conformant). For example, there is a bug in the event subscription renewal function where the camera does not set the proper subscription termination time.  However this particular issue should not cause any apparent problems to the user.

Other camera models return an incorrect subscription reference address used for subscription renewal requests, however this known issue is accounted for in the driver code.  

(These issues expose themselves in the *ONVIF Device Manager* application, which is either unable to show events at all, or the event display stops working after a minute or so.)

Confirmed *not* to work:  Model E1PRO (cannot be discovered)

### Hikvision
- ONVIF must be enabled and a specific ONVIF UserID and Password defined with at least 'Media user' access level (Network->Advanced Settings->Integration Protocol)

- RTSP Authentication must be set to 'digest/basic' (System->Security->Authentication)

- Motion detection should be enabled (Event->Basic Event->Motion Detection)

- Video format must be H264 or H264+ for video streaming to work in the SmartThings mobile app.  Due to SmartThings limitations the maximum size for screen resolution is 1920 x 1080
