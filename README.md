# NetGuard

*NetGuard* provides simple and advanced ways to block access to the internet - no root required.
Applications and addresses can individually be allowed or denied access to your Wi-Fi and/or mobile connection.

Blocking access to the internet can help:

* reduce your data usage
* save your battery
* increase your privacy

NetGuard is the first free and open source no-root firewall for Android.

Features:

* Simple to use
* No root required
* 100% open source
* No calling home
* No tracking or analytics
* Actively developed and supported
* Android 5.1 and later supported
* IPv4/IPv6 TCP/UDP supported
* Tethering supported
* Optionally allow when screen on
* Optionally block when roaming
* Optionally block system applications
* Optionally forward ports, also to external addresses (not available if installed from the Play store)
* Optionally notify when an application accesses the internet
* Optionally record network usage per application per address
* Optionally [block ads using a hosts file](https://github.com/M66B/NetGuard/blob/master/ADBLOCKING.md) (not available if installed from the Play store)
* Material design theme with light and dark theme

PRO features:

* Log all outgoing traffic; search and filter access attempts; export PCAP files to analyze traffic
* Allow/block individual addresses per application
* New application notifications; configure NetGuard directly from the notification
* Display network speed graph in a status bar notification
* Select from five additional themes in both light and dark version

There is no other no-root firewall offering all these features.

Requirements:

* Android 5.1 or later
* A [compatible device](#compatibility)

Downloads:

* [GitHub](https://github.com/M66B/NetGuard/releases)
* [Google Play](https://play.google.com/store/apps/details?id=eu.faircode.netguard)

Certificate fingerprints:

* MD5: B6:4A:E8:08:1C:3C:9C:19:D6:9E:29:00:46:89:DA:73
* SHA1: EF:46:F8:13:D2:C8:A0:64:D7:2C:93:6B:9B:96:D1:CC:CC:98:93:78
* SHA256: E4:A2:60:A2:DC:E7:B7:AF:23:EE:91:9C:48:9E:15:FD:01:02:B9:3F:9E:7C:9D:82:B0:9C:0B:39:50:00:E4:D4

Usage:

* Enable the firewall using the switch in the action bar
* Allow/deny Wi-Fi/mobile internet access using the icons along the right side of the application list

You can use the settings menu to change from blacklist mode (allow all in *Settings* but block unwanted applications in list) to whitelist mode (block all in *Settings* but allow favorite applications in list).

* Red/orange/yellow/amber = internet access denied
* Teal/blue/purple/grey = internet access allowed

<img src="https://raw.githubusercontent.com/M66B/NetGuard/master/screenshots/01-main.png" width="320" height="569" />
<img src="https://raw.githubusercontent.com/M66B/NetGuard/master/screenshots/02-main-details.png" width="320" height="569" />
<img src="https://raw.githubusercontent.com/M66B/NetGuard/master/screenshots/03-main-access.png" width="320" height="569" />
<img src="https://raw.githubusercontent.com/M66B/NetGuard/master/screenshots/08-notifications.png" width="320" height="569" />

For more screenshots, see [here](https://github.com/M66B/NetGuard/tree/master/screenshots).

Compatibility
-------------

The only way to build a no-root firewall on Android is to use the Android VPN service.
Android doesn't allow chaining of VPN services, so you cannot use NetGuard together with other VPN based applications.
See also [this FAQ](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq2).

NetGuard can be used on rooted devices too and even offers more features than most root firewalls.

Some older Android versions, especially Samsung's Android versions, have a buggy VPN implementation,
which results in Android refusing to start the VPN service in certain circumstances,
like when there is no internet connectivity yet (when starting up your device)
or when incorrectly requiring manual approval of the VPN service again (when starting up your device).
NetGuard will try to workaround this and remove the error message when it succeeds, else you are out of luck.

Some LineageOS versions have a broken Android VPN implementation, causing all traffic to be blocked,
please see [this FAQ](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq51) for more information.

NetGuard is not supported for apps installed in a [work profile](https://developer.android.com/work/managed-profiles),
or in a [Secure Folder](https://www.samsung.com/uk/support/mobile-devices/what-is-the-secure-folder-and-how-do-i-use-it/) (Samsung),
or as second instance (MIUI), or as Parallel app (OnePlus),
because the Android VPN service too often does not work correctly in this situation, which can't be fixed by NetGuard.

Filtering mode cannot be used on [CopperheadOS](https://copperhead.co/android/).

NetGuard will not work or crash when the package *com.android.vpndialogs* has been removed or otherwise is unavailable.
Removing this package is possible with root permissions only.
If you disable this package, you can enable it with this command again:

```
adb shell pm enable --user 0 com.android.vpndialogs
```

NetGuard is supported for phones and tablets only, so not for other device types like on a television or in a car.

Android does not allow incoming connections (not the same as incoming traffic) and the Android VPN service has no support for this either.
Therefore managing incoming connections for servers running on your device is not supported.

Wi-Fi or IP calling will not work if your provider uses [IPsec](https://en.wikipedia.org/wiki/IPsec) to encrypt your phone calls, SMS messages and/or MMS messages,
unless there was made an exception in NetGuard for your provider (currently for T-Mobile and Verizon).
I am happy to add exceptions for other providers, but I need the [MCC](https://en.wikipedia.org/wiki/Mobile_country_code) codes, [MNC](https://en.wikipedia.org/wiki/MNC) codes and [IP address](https://en.wikipedia.org/wiki/IP_address) ranges your provider is using.
As an alternative you can enable the option '*Disable on call*', which is available since version 2.113.


<a name="FAQ"></a>
Frequently Asked Questions (FAQ)
--------------------------------

<a name="FAQ0"></a>
[**(0) How do I use NetGuard?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq0)

<a name="FAQ1"></a>
[**(1) Can NetGuard completely protect my privacy?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq1)

<a name="FAQ2"></a>
[**(2) Can I use another VPN application while using NetGuard?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq2)

<a name="FAQ3"></a>
[**(3) Can I use NetGuard on any Android version?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq3)

<a name="FAQ4"></a>
[**(4) Will NetGuard use extra battery power?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq4)

<a name="FAQ6"></a>
[**(6) Will NetGuard send my internet traffic to an external (VPN) server?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq6)

<a name="FAQ7"></a>
[**(7) Why are applications without internet permission shown?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq7)

<a name="FAQ8"></a>
[**(8) What do I need to enable for the Google Play™ store app to work?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq8)

<a name="FAQ9"></a>
[**(9) Why is the VPN service being restarted?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq9)

<a name="FAQ10"></a>
[**(10) Will you provide a Tasker plug-in?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq10)

<a name="FAQ13"></a>
[**(13) How can I remove the ongoing NetGuard entry in the notification screen?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq13)

<a name="FAQ14"></a>
[**(14) Why can't I select OK to approve the VPN connection request?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq14)

<a name="FAQ15"></a>
[**(15) Are F-Droid builds supported?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq15)

<a name="FAQ16"></a>
[**(16) Why are some applications shown dimmed?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq16)

<a name="FAQ17"></a>
[**(17) Why is NetGuard using so much memory?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq17)

<a name="FAQ18"></a>
[**(18) Why can't I find NetGuard in the Google Play™ store app?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq18)

<a name="FAQ19"></a>
[**(19) Why does application XYZ still have internet access?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq19)

<a name="FAQ20"></a>
[**(20) Can I Greenify/hibernate NetGuard?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq20)

<a name="FAQ21"></a>
[**(21) Does doze mode affect NetGuard?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq21)

<a name="FAQ22"></a>
[**(22) Can I tether (use the Android hotspot) / use Wi-Fi calling while using NetGuard?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq22)

<a name="FAQ24"></a>
[**(24) Can you remove the notification from the status bar?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq24)

<a name="FAQ25"></a>
[**(25) Can you add a 'select all'?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq25)

<a name="FAQ27"></a>
[**(27) How do I read the blocked traffic log?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq27)

<a name="FAQ28"></a>
[**(28) Why is Google connectivity services allowed internet access by default?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq28)

<a name="FAQ29"></a>
[**(29) Why do I get 'The item you requested is not available for purchase'?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq29)

<a name="FAQ30"></a>
[**(30) Can I also run AFWall+ on the same device?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq30)

<a name="FAQ31"></a>
[**(31) Why can some applications be configured as a group only?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq31)

<a name="FAQ32"></a>
[**(32) Why is the battery/network usage of NetGuard so high**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq32)

<a name="FAQ33"></a>
[**(33) Can you add profiles?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq33)

<a name="FAQ34"></a>
[**(34) Can you add the condition 'when on foreground'?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq34)

<a name="FAQ35"></a>
[**(35) Why does the VPN not start?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq35)

<a name="FAQ36"></a>
[**(36) Can you add PIN or password protection?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq36)

<a name="FAQ37"></a>
[**(37) Why are the pro features so expensive?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq37)

<a name="FAQ38"></a>
[**(38) Why did NetGuard stop running?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq38)

<a name="FAQ39"></a>
[**(39) How does a VPN based firewall differ from a iptables based firewall?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq39)

<a name="FAQ40"></a>
[**(40) Can you add schedules?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq40)

<a name="FAQ41"></a>
[**(41) Can you add wildcards?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq41)

<a name="FAQ42"></a>
[**(42) Why is permission ... needed?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq42)

<a name="FAQ43"></a>
[**(43) I get 'This app is causing your device to run slowly'**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq43)

<a name="FAQ44"></a>
[**(44) I don't get notifications on access**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq44)

<a name="FAQ45"></a>
[**(45) Does NetGuard handle incoming connections?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq45)

<a name="FAQ46"></a>
[**(46) Can I get a refund?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq46)

<a name="FAQ47"></a>
[**(47) Why are there in application advertisements?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq47)

<a name="FAQ48"></a>
[**(48) Why are some domain names blocked while they are set to be allowed?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq48)

<a name="FAQ49"></a>
[**(49) Does NetGuard encrypt my internet traffic / hide my IP address?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq49)

<a name="FAQ50"></a>
[**(50) Will NetGuard automatically start on boot?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq50)

<a name="FAQ51"></a>
[**(51) NetGuard blocks all internet traffic!**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq51)

<a name="FAQ52"></a>
[**(52) What is lockdown mode?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq52)

<a name="FAQ53"></a>
[**(53) The translation in my language is missing / incorrect / incomplete!**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq53)

<a name="FAQ54"></a>
[**(54) How to tunnel all TCP connections through the Tor network?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq54)

<a name="FAQ55"></a>
[**(55) Why does NetGuard connect to Amazon / ipinfo.io?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq55)

<a name="FAQ56"></a>
[**(56) NetGuard allows all internet traffic!**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq56)

<a name="FAQ57"></a>
[**(57) Why does NetGuard use so much data?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq57)

<a name="FAQ58"></a>
[**(58) Why does loading the application list take a long time?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq58)

<a name="FAQ59"></a>
[**(59) Can you help me restore my purchase?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq59)

<a name="FAQ60"></a>
[**(60) Why does IP (Wi-Fi) calling/SMS/MMS not work?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq60)

<a name="FAQ61"></a>
[**(61) Help, NetGuard crashed!**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq61)

<a name="FAQ62"></a>
[**(62) How can I solve 'There was a problem parsing the package' ?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq62)

<a name="FAQ63"></a>
[**(63) Why is all DNS traffic allowed?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq63)

<a name="FAQ64"></a>
[**(64) Can you add DNS over TLS?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq64)

<a name="FAQ65"></a>
[**(65) Why can NetGuard not block itself?**](https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq65)

Support
-------

For questions, feature requests and bug reports, please [use this XDA-Developers forum thread](http://forum.xda-developers.com/showthread.php?t=3233012).

There is support on the latest version of NetGuard only.

There is no support on things that are not directly related to NetGuard.

There is no support on building and developing things by yourself.

**NetGuard is supported for phones and tablets only, so not for other device types like on a television or in a car.**

Contributing
------------

*Building*

Building is simple, if you install the right tools:

* [Android Studio](http://developer.android.com/sdk/)
* [Android NDK](http://developer.android.com/tools/sdk/ndk/)

The native code is built as part of the Android Studio project.

It is expected that you can solve build problems yourself, so there is no support on building.
If you cannot build yourself, there are prebuilt versions of NetGuard available [here](https://github.com/M66B/NetGuard/releases).

*Translating*

* Translations to other languages are welcomed
* You can translate online [here](https://crowdin.com/project/netguard/)
* If your language is not listed, please send a message to marcel(plus)netguard(at)faircode(dot)eu
* You can see the status of all translations [here](https://crowdin.com/project/netguard).

Please note that by contributing you agree to the license below, including the copyright, without any additional terms or conditions.

Attribution
-----------

NetGuard uses:

* [Glide](https://bumptech.github.io/glide/)
* [Android Support Library](https://developer.android.com/tools/support-library/)

License
-------

[GNU General Public License version 3](http://www.gnu.org/licenses/gpl.txt)

Copyright (c) 2015-2018 Marcel Bokhorst ([M66B](https://contact.faircode.eu/))

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

Trademarks
----------

*Android is a trademark of Google Inc. Google Play is a trademark of Google Inc*
