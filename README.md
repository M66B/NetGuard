# NetGuard

*NetGuard* provides a simple way to block access to the internet - no root required.
Applications can individually be allowed or denied access to your Wi-Fi and/or mobile connection.

Blocking access to the internet can help:

* reduce your data usage
* save your battery
* increase your privacy

NetGuard is possibly the first free and open source no-root firewall for Android.

Features:

* No root required
* Simple to use
* Free of charge
* Open source
* No extra battery usage
* No bandwidth reduction
* No calling home
* No tracking or analytics
* No ads
* No internet permission required
* IPv4/IPv6 TCP/UDP supported
* Optionally allow when screen on
* Optionally block when roaming
* Optionally block system applications
* Material design

Most of these features are the result of sending selected traffic to a sinkhole, instead of filtering all internet traffic.
This means that advanced features, like address based filtering (needed for ad blocking), traffic logging, and on-demand configuration, are not possible.
Routing selected traffic into a sinkhole relies on an API introduced in Android 5.0 (Lollipop),
therefore older Android versions unfortunately cannot be supported.

Since NetGuard has no internet permission, you know your internet traffic is not being sent anywhere.

Downloads:

* [GitHub](https://github.com/M66B/NetGuard/releases)
* [Play store](https://play.google.com/store/apps/details?id=eu.faircode.netguard) (stable)
* [Play store](https://play.google.com/apps/testing/eu.faircode.netguard) (beta)
* [F-Droid](https://f-droid.org/repository/browse/?fdfilter=netguard&fdid=eu.faircode.netguard) (unsupported, often outdated)
* [XDA Labs App](http://forum.xda-developers.com/android/apps-games/labs-t3241866) ([web page](https://labs.xda-developers.com/store/app/eu.faircode.netguard))

Usage:

* Enable the firewall using the switch in the action bar
* Allow/deny Wi-Fi/mobile internet access using the icons along the right side of the application list

<img src="screenshot1.png" width="320" height="569" />

<img src="screenshot2.png" width="320" height="569" />

Compatibility
-------------

Devices / ROMs with a broken VPN implementation:

* Alcatel™ OneTouch Idol 3 / Android 5.0.2 (reported in the Play store) (all traffic blocked)
* Asus™ ZenFone 2 / Android 5.0.2/5.1.1, [reported on XDA](http://forum.xda-developers.com/showpost.php?p=63619542&postcount=121) (all traffic blocked)
* Asus™ ZenFone 4 / Android 5.0 (reported in the Play store) (all traffic blocked)
* BQ™ Aquaris M5 / Android 5.0 (reported in the Play store) (all traffic blocked)
* Lenovo™ Yoga Tablet Pro-1380L / 2 Pro / Android 5.0.1, [reported on XDA](http://forum.xda-developers.com/showpost.php?p=63784102&postcount=278) (all traffic blocked)
* Samsung™ Galaxy A5 / Android 5.0.2, [reported on Github](https://github.com/M66B/NetGuard/issues/20) (all traffic blocked)
* Sony™ Xperia™ M4 Aqua Dual / Android 5.0 (reported in the Play store) (all traffic blocked)

NetGuard will crash when the package *com.android.vpndialogs* has been removed or otherwise is unavailable.

Tethering will not work when NetGuard is enabled due to a bug in Android ([issue](https://github.com/M66B/NetGuard/issues/42)).

Unfortunately it is not possible to workaround any of these problems.

<a name="FAQ"></a>
Frequently Asked Questions (FAQ)
--------------------------------

<a name="FAQ1"></a>
**(1) Can NetGuard completely protect my privacy?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ1).

<a name="FAQ2"></a>
**(2) Can I use VPN applications while using NetGuard?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ2).

<a name="FAQ3"></a>
**(3) Can I use NetGuard on any Android version?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ3).

<a name="FAQ4"></a>
**(4) Will NetGuard use extra battery power?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ4).

<a name="FAQ5"></a>
**(5) Can you add selective allowing/blocking applications/IP addresses?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ5).

<a name="FAQ6"></a>
**(6) Will NetGuard send my internet traffic to an external (VPN) server?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ6).

<a name="FAQ7"></a>
**(7) Why are applications without internet permission shown?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ7).

<a name="FAQ8"></a>
**(8) What do I need to enable for the Google Play Store to work?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ8).

<a name="FAQ9"></a>
**(9) Why is the VPN service being restart?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ9).

<a name="FAQ10"></a>
**(10) Will you provide a Tasker plug-in?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ10).

<a name="FAQ12"></a>
**(12) Can you add on demand asking to block/allow access?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ12).

<a name="FAQ13"></a>
**(13) How can I remove the ongoing NetGuard entry in the notification screen?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ13).

<a name="FAQ14"></a>
**(14) Why can't I select OK to approve the VPN connection request?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ14).

<a name="FAQ15"></a>
**(15) Why don't you support F-Droid?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ15).

<a name="FAQ16"></a>
**(16) Why are some applications shown dimmed?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ16).

<a name="FAQ17"></a>
**(17) Why is NetGuard using so much memory?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ17).

<a name="FAQ18"></a>
**(18) Why can I not find NetGuard in the Play store?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ18).

<a name="FAQ19"></a>
**(19) Why does aplication xyz still have internet access?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ19).

<a name="FAQ20"></a>
**(20) Can I Greenify NetGuard?**

This question has been moved [here](https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ20).

Permissions
-----------

* ACCESS_NETWORK_STATE: to check if the device is connected to the internet through Wi-Fi
* RECEIVE_BOOT_COMPLETED: to start the firewall when booting the device
* WAKE_LOCK: to reliably reload rules in the background on connectivity changes
* com.android.vending.BILLING: to accept donations via in-app billing

Support
-------

* Questions: please [use this XDA-Developers forum thread](http://forum.xda-developers.com/showthread.php?t=3233012)
* Feature requests and bugs: please [create an issue on GitHub](https://github.com/M66B/NetGuard/issues/new)

Please do not use GitHub for questions.

Contributing
------------

Translations:

* Translations to other languages are welcomed
* Check if the language [is supported by Android](http://stackoverflow.com/questions/7973023/what-is-the-list-of-supported-languages-locales-on-android) and find its locale
* Copy [this file](https://github.com/M66B/NetGuard/blob/master/app/src/main/res/values/strings.xml) to the [correct locale folder](https://github.com/M66B/NetGuard/blob/master/app/src/main/res/)
* Translate the strings in the copied file and omit all lines with **translatable="false"**
* Create a [pull request on GitHub](https://help.github.com/articles/using-pull-requests) for the new/updated translation
* If you don't feel comfortable using GitHub, you can sent the translation to *marcel(plus)netguard(at)faircode.eu*

Current translations:

1. Arabic (ar)
1. Dutch (nl)
1. Simplified Chinese (zh-rCN)
1. English
1. French (fr)
1. German (de)
1. Italian (it)
1. Japanese (ja)
1. Korean (ko)
1. Polish (pl)
1. Romanian (ro)
1. Russian (ru)
1. Slovak (sk)
1. Spanish (es)
1. Ukrainian (uk)

Please note that you agree to the license below by contributing, including the copyright.

Attribution
-----------

NetGuard uses:

* [Picasso](http://square.github.io/picasso/)
* [Android Support Library](https://developer.android.com/tools/support-library/index.html)

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
