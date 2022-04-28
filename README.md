# Edge-ONVIF-Driver
Supports motion detection and streaming from ONVIF-compliant IP cameras
## Pre-requisites
SmartThings hub capable of running Edge platform
SmartThings account
SmartThings mobile app
ONVIF-compliant IP camera supporting Profile S (Streaming) 
## Installation Steps
Use my shared projects Edge channel to complete these steps:
1. Enroll hub in my shared projects Edge channel
2. Choose to install driver 'ONVIF Video Camera V1'

Once the driver is installed to your hub, use the SmartThings mobile app to initiate an Add device -> Scan nearby devices.  Your ONVIF-compliant IP cameras will be discovered and SmartThings devices added to the 'No room assigned' room.

After discovery is complete, go in to each device Settings screen and set the configuration optins.

### Device Settings

#### Minimum motion-active interval
Use this setting to eliminate multiple rapid motion alerts.

Values can be any number of seconds up to 3,600 (one hour).  For example a value of 10 means allow only one motion alert within a 10 second period.  A value of 0 effectively turns this option off.  Note that some cameras allow a similar configuration setting through the manufacturer app.

#### Auto motion revert
Use this setting to force motion to inactive regardless of when the event is received from the camera.

#### Auto-revert delay
Use this setting when Auto motion revert is set to 'Auto-revert'.  

Value provided is the number of seconds to wait - after an active motion is received - to revert motion to inactive.

#### Event Subscription
For future use to select ONFIV subscription type to accommodate various camera capabilities

#### UserID and Password
This is the access credentials required to access your camera, initially set up in the camera manufacturer's app
