
this is a small script for Vista+ machines which allows you to block
domains using wildcard matches. This script should be run as admin. 

This will have no effect on connections using hardcoded ip addresses.
As it runs it will show you the name and PID of the responsible process.

it is currently set to block Windows 10 updates, telemetry
and other Win10 call home features. 

This depends on 2 python packages. The script will detect if they are missing
and can auto install them if you allow it. You can also manually install them
with pip:

pip install pydivert
pip install dnslib

The pydivert/WinDivert library allows for the interception and manipulation of
network traffic. This is only active while the python script is running. 

You configure it through config.txt. Here you can set processes and domains to be white 
or black listed. All entries support wildcard matches and are case insensitive.

You have to restart the script for config changes to be recgonized. 

Blocked requests have localhost returned in the dns response. 
All other requests will be allowed to pass through normally. 

to see blocked requests in real time you can use the /show command line option.

The port to process routines in winutil.py, and general know how for this code was 
taken from the FireEye FakeNet-NG project designed by Peter Kacherginsky

Many thanks goes out to all the authors involved:

FakeNet-NG
  Author: Peter Kacherginsky
    Link: https://github.com/fireeye/flare-fakenet-ng

Windivert
  Author: basil
    Link: https://reqrypt.org/windivert.html

pydivert
  Author: Fabio Falcinelli  
  Author: Maximilian Hils  
    Link: https://github.com/ffalcinelli/pydivert

dnslib
  Author: Paul Chakravart
    Link: https://bitbucket.org/paulc/dnslib