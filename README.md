# NetGuard

NetGuard is possibly the first free and open source no root firewall for Android.

<img src="screenshot.png" width="232" height="371" hspace="4"/>

Features
--------

* No root required
* Simple to use
* Free and open source
* No calling home
* No ads

Usage
-----

* Enable the firewall using the switch in the action bar
* Allow/deny Wi-FI/mobile internet access using the icons at the right side of the application list

Permissions
-----------

* ACCESS_NETWORK_STATE: to check if the device is connected to the internet through Wi-Fi
* RECEIVE_BOOT_COMPLETED: to start the firewall when starting the device

Frequently asked questions
--------------------------

<a name="FAQ1"></a>
**(1) Can NetGuard protect my privacy?**

Not really, since the firewall cannot be started right after starting your device
and because updating firewall rules require momentarily turning off the firewall.

<a name="FAQ2"></a>
**(2) Can I use VPN applications while using NetGuard?**

If the VPN application is using the Android [VPN service](http://developer.android.com/reference/android/net/VpnService.html),
then no, because NetGuard needs to use this service too and Android allows this to just one application at a time.

Contributing
------------

Please note that you agree to the license below by contributing, including the copyright.


License
-------

[GNU General Public License version 3](http://www.gnu.org/licenses/gpl.txt)

Copyright (c) 2015 Marcel Bokhorst ([M66B](http://forum.xda-developers.com/member.php?u=2799345))

All rights reserved

This file is part of NetGuard.

NetGuard is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your discretion) any later version.

NetGuard is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with NetGuard. If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).
