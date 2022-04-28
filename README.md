# Edge-ONVIF-Driver
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

Once the driver is installed to your hub, use the SmartThings mobile app to initiate an Add device -> Scan nearby devices.  Your ONVIF-compliant IP cameras will be discovered and SmartThings devices added to the 'No room assigned' room.

After discovery is complete, go in to each device Settings screen and set the configuration options described below.

### Device Configuration Settings

#### Minimum motion-active interval
Use this setting to eliminate multiple rapid motion alerts.  This can be useful if you have routines triggered by motion events, and it also cuts down the number of state changes sent to SmartThings, as well as captured in device history.

Values can be any number of seconds up to 3,600 (one hour).  For example a value of 10 means allow only one motion alert within a 10 second window.  A value of 0 effectively turns this option off.  Note that some cameras allow a similar configuration setting through the manufacturer app.

#### Auto motion revert
Use this setting to force motion to inactive regardless of when/if the inactive event is received from the camera.

#### Auto-revert delay
Use this setting when Auto motion revert is set to 'Auto-revert'.  

Value provided is the number of seconds to wait - after an active motion is received - to revert motion to inactive.

#### Event Subscription
For future use to select ONFIV subscription type to accommodate various camera capabilities

#### UserID and Password
This is the access credentials required to access your camera, initially set up in the camera manufacturer's app

### Camera Connection Status
Once a UserID and Password is provided, connection to the camera will be initiated where additional information will be obtained from the camera and initialization done to enable video streaming and reporting of motion events.  At any time, device history can be examined to see connection status and camera metadata obtained.


## Notes on Specific Camera Brands
The official list of camera models that have passed ONVIF certification can be found at this website:  https://www.onvif.org/conformant-products/.

Even if your camera is not listed there, check the manufacturers documentation to see if they claim ONVIF compatibility.  It should be noted that although a manufacturer may claim ONVIF compliance, it may not be a complete, or fully-functional implementation if it is not on the official conformant product list noted above.  Check the SmartThings community topic for reports on what cameras are working with this driver.

ONVIF defines specific Profiles, which define the feature the camera supports.  This driver requires only the Streaming Profile (Profile S).

If a camera cannot be discovered, then it probably doesn't support ONVIF.

To date, this driver has been tested with Reolink and Hikvision cameras.

#### Reolink
Many Reolink cameras should work with this driver, but not all.  
Confirmed *not* to work:  Model E1PRO

#### Hikvision
- ONVIF must be enabled and a specific ONVIF UserID and Password defined with at least 'Media user' access level (Network->Advanced Settings->Integration Protocol)

- RTSP Authentication must be set to 'digest/basic' (System->Security->Authentication)

- Enable motion detection (Event->Basic Event->Motion Detection)

- Video format must be H264 or H264+ for streaming to work in SmartThings
