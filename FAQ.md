NetGuard
========

Please scroll down if you want to ask a question, request a feature or report a bug.

Frequently Asked Questions (FAQ)
--------------------------------

<a name="FAQ0"></a>
**(0) How do I use NetGuard?**

* Enable the firewall using the switch in the action bar
* Allow (greenish) or deny (reddish) Wi-Fi or mobile internet access using the icons next to an application

You can use the settings menu to change from blacklist mode (allow all in *Settings* but block unwanted applications in list) to whitelist mode (block all in *Settings* but allow favorite applications in list).

* Red/orange/yellow/amber = internet access denied
* Teal/blue/purple/grey = internet access allowed

<a name="FAQ1"></a>
**(1) Can NetGuard completely protect my privacy?**

No - nothing can completely protect your privacy.
NetGuard will do its best, but it is limited by the fact it must use the VPN service.
This is the trade-off required to make a firewall which does not require root access.
The firewall can only start when Android "allows" it to start,
so it will not offer protection during early boot-up (although your network may not be loaded at that time).
It will, however, be much better than nothing, especially if you are not rebooting often.

Android N will allow NetGuard to be an [Always-On VPN](https://developer.android.com/preview/features/afw.html#always-on-vpn).

If you want to protect yourself more, you can (at least in theory) disable Wi-Fi and mobile data before rebooting,
and only enable them on reboot, after the firewall service has started (and the small key icon is visible in the status bar).

Thanks @[pulser](https://github.com/pulser/)

<a name="FAQ2"></a>
**(2)  Can I use another VPN application while using NetGuard**

If the VPN application is using the [VPN service](http://developer.android.com/reference/android/net/VpnService.html),
then no, because NetGuard needs to use this service. Android allows only one application at a time to use this service.

NetGuard is a firewall application, so there is no intention to add VPN support.
However, NetGuard supports a [SOCKS5 proxy](https://en.wikipedia.org/wiki/SOCKS) to chain VPN applications.

<a name="FAQ3"></a>
**(3) Can I use NetGuard on any Android version?**

No, the minimum required Android version is 4.0 (<a href= "https://developer.android.com/about/versions/android-4.0.html">ICE_CREAM_SANDWICH</a>)
because NetGuard uses the [Android VPN service](https://developer.android.com/reference/android/net/VpnService.html),
which was added in Android 4.0.

<a name="FAQ4"></a>
**(4) Will NetGuard use extra battery power?**

If you didn't enable IP filtering, probably not.

However, the network speed graph notification will use extra battery power.
This is why the notification is shown only when the screen is on.
You can decrease the update frequency using the settings to reduce the battery usage.

The battery usage when IP filtering is enabled depends on the quality of your Android VPN service implementation and the efficiency of the CPU of your device.
Generally the battery usage on older devices might be unacceptable and hardly noticeable on modern devices with an efficient CPU.

Note that Android often (incorrectly) contribute battery usage of other applications to NetGuard,
because the network traffic of other applications is flowing through NetGuard.

<a name="FAQ6"></a>
**(6) Will NetGuard send my internet traffic to an external (VPN) server?**

No, depending on the mode of operation basically one of two things will happen with your internet traffic:

* When IP filtering is disabled, blocked internet traffic will be routed into the local VPN which will operate as sinkhole (in effect dropping all blocked traffic)
* When IP filtering is enabled, both blocked and allowed internet traffic will be routed into the local VPN and only allowed traffic will be forwarded to the intended destination (so not to a VPN server)

The [Android VPN service](http://developer.android.com/reference/android/net/VpnService.html) is being used to locally route all internet traffic to NetGuard so no root is required to build a firewall application.
NetGuard is unlike all other no-root firewalls applications 100% open source, so when you are in doubt you can check [the source code](https://github.com/M66B/NetGuard/) yourself.

<a name="FAQ7"></a>
**(7) Why are applications without internet permission shown?**

Internet permission can be granted with each application update without user consent.
By showing all applications, NetGuard allows you to control internet access even *before* such an update occurs.

<a name="FAQ8"></a>
**(8) What do I need to enable for the Google Play™ store app to work?**

You need 3 packages (applications) enabled (use search in NetGuard to find them quickly):

* com.android.vending (Play store)
* com.google.android.gms (Play services)
* com.android.providers.downloads (Download manager)

Since the Google Play™ store app has a tendency to check for updates or even download them all by itself (even if no account is associated),
one can keep it in check by enabling "*Allow when device in use*" for all 3 of these packages.
Click on the down arrow on the left side of an application name and check that option,
but leave the network icons set to red (hence blocked).The little human icon will appear for those packages.

Note that NetGuard does not require any Google service to be installed.

<a name="FAQ9"></a>
**(9) Why is the VPN service being restarted?**

The VPN service will be restarted when you turn the screen on or off and when connectivity changes (Wi-Fi, mobile)
to apply the rules with the conditions '*Allow when screen is on*' and '*Block when roaming*'.

See [here](http://forum.xda-developers.com/showpost.php?p=65723629&postcount=1788) for more details.

<a name="FAQ10"></a>
**(10) Will you provide a Tasker plug-in?**

If disabling NetGuard is allowed to Tasker, any application can disabled NetGuard too.
Allowing to disable a security application from other applications is not a good idea.

<a name="FAQ13"></a>
**(13) How can I remove the ongoing NetGuard entry in the notification screen?**

* Long click the NetGuard notification
* Tap the 'i' icon
* Depending on your device and/or ROMs manufacturer software customizations, you can be directed to either:
  * the **App Info** screen and you can uncheck '*Show notifications*' and agree to the next dialog
  * the **App Notifications** screen and you can toggle the '*Block*' slider to on

Note that, whether or not you get a dialog warning to agree upon,
this operation will disable any information or warning notifications from NetGuard as well,
like the new application installed notification.

To read about the need for the notification in the first place, see [question 24](#FAQ24).

Some Android versions display an additional notification, which might include a key icon.
This notification can unfortunately not be removed.

<a name="FAQ14"></a>
**(14) Why can't I select OK to approve the VPN connection request?**

There might be another (invisible) application on top of the VPN connection request dialog.
Some known (screen dimming) applications which can cause this are *Lux Brightness*, *Night Mode* and *Twilight*.
To avoid this problem, at least temporary, close all applications and/or services which may be running in the background.

<a name="FAQ15"></a>
**(15) Why won't you support the F-Droid builds?**

Because F-Droid doesn't support reproducible builds.
Read [here](https://blog.torproject.org/blog/deterministic-builds-part-one-cyberwar-and-global-compromise) why this is important.

Another reason is that F-Droid builds are more often than not outdated, leaving users with an old version with known bugs.

<a name="FAQ16"></a>
**(16) Why are some applications shown dimmed?**

Disabled applications and applications without internet permission are shown dimmed.

<a name="FAQ17"></a>
**(17) Why is NetGuard using so much memory?**

It isn't, NetGuard doesn't allocate any memory, except a little for displaying the user interface elements.
It appeared that on some Android variants the Google Play™ store app connection, using almost 150 MB and needed for in-app donations,
is incorrectly attributed to NetGuard instead to the Google Play™ store app.

<a name="FAQ18"></a>
**(18) Why can't I find NetGuard in the Google Play™ store app?**

NetGuard requires at least Android 4.0, so it is not available in the Google Play™ store app for devices running older Android versions.

<a name="FAQ19"></a>
**(19) Why does application XYZ still have internet access?**

If you block internet access for an application, there is no way around it.
However, applications could access the internet through other (system) applications.
Google Play services is handling incoming push messages for most applications for example.
You can prevent this by blocking internet access for the other application as well.
This can best be diagnosed by checking the global access log (three dot menu, Show log).

Note that some applications keep trying to access the internet, which is done by sending a connection request packet.
This packet goes into the VPN sinkhole when internet access for the application is blocked.
This packet consists of less than 100 bytes and is counted by Android as outgoing traffic
and will be visible in the speed graph notification as well.

<a name="FAQ20"></a>
**(20) Can I Greenify/hibernate NetGuard?**

No. [Greenifying](https://play.google.com/store/apps/details?id=com.oasisfeng.greenify)
or otherwise hibernating NetGuard will result in rules not being applied
when connectivity changes from Wi-Fi/mobile, screen on/off and roaming/not roaming.

<a name="FAQ21"></a>
**(21) Does doze mode affect NetGuard?**

I am not sure, because the [doze mode documentation](http://developer.android.com/training/monitoring-device-state/doze-standby.html)
is not clear if the [Android VPN service](http://developer.android.com/reference/android/net/VpnService.html) will be affected.

To be sure you can disable battery optimizations for NetGuard manually like this:

```
Android settings > Battery > three dot menu > Battery optimizations > Dropdown > All apps > NetGuard > Don't optimize > Done
```

This cannot be done from the application,
because according to Google NetGuard is [not an application type allowed to do this](http://developer.android.com/training/monitoring-device-state/doze-standby.html#whitelisting-cases).

<a name="FAQ22"></a>
**(22) Can I tether / use Wi-Fi calling while using NetGuard?**

Yes, but this needs to be enabled in the settings.
If it works depends on your Android version,
because some Android versions have a bug preventing tethering and the VPN service to work together.

Some devices hibernate Wi-Fi preventing tethering to work when the screen is off.
This behavior can be disabled in the Android enhanced/advanced Wi-Fi settings.

<a name="FAQ24"></a>
**(24) Can you remove the notification from the status bar?**

Android can kill background services at any time.
This can only be prevented by turning a background service into a foreground service.
Android requires an ongoing notification for all foreground services
to make you aware of potential battery usage (see [question 4](#FAQ4)).
So, the notification cannot be removed without causing instability.
However, the notification is being marked as low priority,
which should result in moving it to the bottom of the list.

The key icon and/or the VPN running notification,
which is shown by Android and not by NetGuard, can unfortunately not be removed.
The [Google documentation](http://developer.android.com/reference/android/net/VpnService.html) says:
"*A system-managed notification is shown during the lifetime of a VPN connection*".

<a name="FAQ25"></a>
**(25) Can you add a 'select all'?**

There is no need for a select all function,
because you can switch from black list to white list mode using the settings.
See also [question 0](#FAQ0).

<a name="FAQ27"></a>
**(27) How do I read the blocked traffic log?**

The columns have the following meaning:

1. Time (tap on a log entry to see the date)
1. Application icon (tap on a log entry to see the application name)
1. Application UID
1. Wi-Fi / mobile connection, green=allowed, red=blocked
1. Interactive state (screen on or off)
1. Protocol (see below) and packet flags (see below)
1. Source and destination port (tap on a log entry to lookup a destination port)
1. Source and destination IPv4 or IPv6 address (tap on a log entry to lookup a destination IP address)
1. Organization name owning the IP address (need to be enabled through the menu)

Protocols:

* HOPO (IPv6 Hop-by-Hop Option)
* ICMP
* IGMP
* ESP (IPSec)
* TCP
* UDP
* Number = one of the protocols in [this list](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
* 4 = IPv4
* 6 = IPv6

Packet flags:

* S = SYN
* A = ACK
* P = PSH
* F = FIN
* R = RST

For a detailed explanation see [here](https://en.wikipedia.org/wiki/Transmission_Control_Protocol).

Only TCP, UDP and ICMP ping traffic can be routed through the Android VPN service.
All other traffic will be dropped and will be shown as blocked in the global traffic log.
This is almost never a problem on an Android device.

<a name="FAQ28"></a>
**(28) Why is Google connectivity services allowed internet access by default?**

The Google connectivity services system application checks if the current network is really connected to the internet.
This is probably done by briefly connecting to some Google server.

If this is not the case, there will be an '!' in the Wi-Fi or mobile icon in the system status bar.

Recent Android versions seem not to switch connectivity from mobile to Wi-Fi when the Wi-Fi network is not really connected,
even though there is a connection to the Wi-Fi network (or the other way around). On Android 6.0 and later you might get a notification asking you if you want to keep this connection on or not.
To prevent a bad user experience there is a predefined rule to default allow the Google connectivity services.

You can find all predefined rules [here](https://github.com/M66B/NetGuard/blob/master/app/src/main/res/xml/predefined.xml).

<a name="FAQ29"></a>
**(29) Why do I get 'The item you requested is not available for purchase'?**

You can only purchase pro features when you installed NetGuard from the Play store.

<a name="FAQ30"></a>
**(30) Can I also run AFWall+ on the same device?**

Unless you are just testing NetGuard, there is no current reason to use them both, since they cover the same function (firewall),
although with different base needs (AFWall+ needs a rooted device) and ways of doing their thing (AFWall+ uses iptables).

Also you need to keep per application access rules _always_ in sync,
else the application will not be able to access the network,
hence bringing another level of complexity when setting and assuring things work out.

Some pointers on how to set up AFWall+:
* if not using filtering in NetGuard, applications _need_ direct internet access (Wi-Fi and/or mobile) in AFWall+
* if using filtering, NetGuard will _need_ internet access (Wi-Fi and/or mobile) in AFWall+
* if using filtering, when you un/reinstall NetGuard, remember to RE-allow NetGuard in AFWall+
* if using filtering, applications _need_ VPN internet access (check the box to show that option in AFWall+ settings)

<a name="FAQ31"></a>
**(31) Why can some applications be configured as a group only?**

For a lot of purposes, including network access, Android groups applications on UID and not on package/application name.
Especially system applications often have the same UID, despite having a different package and application name, these are set up like this by the ROM manufacturer at build time.
These applications can only be allowed/blocked access to the internet as a group.

<a name="FAQ32"></a>
**(32) Why is the battery/network usage of NetGuard so high?**

This is because Android contributes battery and network usage which is normally contributed to other applications
to NetGuard in IP filtering mode. The total battery usage is slightly higher when IP filtering mode is enabled.
IP filtering mode is always enabled on Android version before 5.0 and optionally enabled on later Android versions.

<a name="FAQ33"></a>
**(33) Can you add profiles?**

Profiles are inconvenient because they need to be operated manually.
Conditions like '*When screen is on*' are on the other hand convenient because they work automatic.
Therefore profiles will not be added, but you are welcome to propose new conditions,
however they need to be generally usable to be included.

As a workaround you can use the export/import function to apply specific settings in specific circumstances.
Alternatively you can use lockdown mode as a profile.

<a name="FAQ34"></a>
**(34) Can you add a condition 'when on foreground' or 'when active'?**

Recent Android versions do not allow an application to query if other applications are in the foreground/background or active/inactive
without holding an [additional privacy violating permission](https://developer.android.com/reference/android/Manifest.permission.html#PACKAGE_USAGE_STATS)
and at the expense of extra battery usage (because periodic polling is required) anymore,
so this cannot be added without significant disadvantages, like [this one](http://www.xda-developers.com/working-as-intended-an-exploration-into-androids-accessibility-lag/).
You can use the condition '*when screen is on*' instead.

<a name="FAQ35"></a>
**(35) Why does the VPN not start?**

NetGuard "asks" Android to start the local VPN service,
but some Android versions contain a bug which prevents the VPN from starting (automatically).
Sometimes this is caused by updating NetGuard.
Unfortunately this cannot be fixed from NetGuard.
What you can try is to restart your device and/or revoke the VPN permissions from NetGuard using the Android settings.
Sometimes it helps to uninstall and install NetGuard again (be sure to export your settings first).

<a name="FAQ36"></a>
**(36) Can you add PIN or password protection?**

Since turning off the VPN service using the Android settings cannot be prevented,
there is little use in adding PIN or password protection.

<a name="FAQ37"></a>
**(37) Why are the pro features so expensive?**

The right question is "*why are there so many taxes and fees*":

* VAT: 25% (depending on your country)
* Google fee: 30%
* Income tax: 50%

So, what is left for the developer is just a fraction of what you pay.

Despite NetGuard being *really* a lot of work, only some of the convenience and advanced features needs to be purchased,
which means that NetGuard is basically free to use
and that you don't need to pay anything to reduce your data usage, increase battery life and increase your privacy.

Also note that most free applications will appear not to be sustainable in the end, whereas NetGuard is properly maintained and supported,
and that free applications may have a catch, like sending privacy sensitive information to the internet.

See [here](http://forum.xda-developers.com/showpost.php?p=67892427&postcount=3030) for some more information.

<a name="FAQ38"></a>
**(38) Why did NetGuard stop running?**

On most devices, NetGuard will keep running in the background with its foreground service.
On some devices (in particular some Samsung models), where there are lots of applications competing for memory, Android may still stop NetGuard as a last resort.
Unfortunately this cannot be fixed from NetGuard, and can be considered a shortcoming of the device and/or as a bug in Android.
You can workaround this problem by enabling the watchdog in the NetGuard advanced options to check every 10-15 minutes.

<a name="FAQ39"></a>
**(39) How does a VPN based firewall differ from a iptables based firewall?**

See this [Stack Exchange question](http://android.stackexchange.com/questions/152087/any-security-difference-between-root-based-firewall-afwall-and-non-root-based).

<a name="FAQ40"></a>
**(40) Can you add schedules?**

Besides not being trivial to add, schedule are in my opion not a good idea, since time is not a good rule condition.
A rule condition like *When screen is on* is a better and more straightforward condition.
Therefore schedules will not be added, but you are welcome to propose other new conditions.

<a name="FAQ41"></a>
**(41) Can you add wildcards?**

Wildcards to allow/block addresses would have a significant performance and usability impact and will therefore not be added.

<a name="FAQ42"></a>
**(42) Why is permission ... needed?**

* INTERNET ('*Full network access*'): to forward allowed (filtered) traffic to the internet
* ACCESS_NETWORK_STATE ('*View network connections*'): to check if the device is connected to the internet through Wi-Fi
* READ_PHONE_STATE ('*Device ID & call information*'): to detect mobile network changes, see [here](http://forum.xda-developers.com/showpost.php?p=64107371&postcount=489) for more details
* ACCESS_WIFI_STATE ('*Wi-Fi connection information*'): to detect Wi-Fi network changes
* RECEIVE_BOOT_COMPLETED ('*Run at startup*'): to start the firewall when booting the device
* WAKE_LOCK ('*Prevent device from sleeping*'): to reliably reload rules in the background on connectivity changes
* READ/WRITE_EXTERNAL_STORAGE ('*Photos/Media/Files*'): to export/import settings on Android versions before 4.4 (KitKat) (there is no need to grant this permission on later Android versions)
* VIBRATE: to give feedback on widget tap
* BILLING: to use in-app billing

<a name="FAQ43"></a>
**(43) I get 'This app is causing your device to run slowly'**

This message is displayed by the *Smart Manager*,
but actually it is the 'Smart' Manager application itself which is causing delays and lags.
Some links:

* [Smart Manager complaining about LastPass](https://www.reddit.com/r/GalaxyS6/comments/3htu2y/smart_manager_cmoplaining_about_lastpass/)
* [Disable Smart Manager?](http://forums.androidcentral.com/samsung-galaxy-s4/595483-disable-smart-manager.html)

<a name="FAQ44"></a>
**(44) I don't get notifications on access**

To prevent a high number of status bar notifications, notify on access is done only once per domain name per application.
Access to domain names shown in the application access log (drill down the NetGuard application settings) will not be notified again,
even if you just enabled notify on access.
To get notified for all domain names again, you can clear the application access log using the waste bin icon.
If you want to clear all applications logs, you can export and import your settings.

<a name="FAQ45"></a>
**(45) Does NetGuard handle incoming connections?**

The Android VPN service handles outgoing connections only (from applications to the internet), so incoming connections are normally left alone.

If you want to run a server application on Android, then be aware that using port numbers below 1024 requires root permissions
and that some Android versions contain routing bugs, causing inbound traffic incorrectly being routed into the VPN.

<a name="FAQ46"></a>
**(46) Can I get a refund?**

If a purchased pro feature doesn't work [as described](https://www.netguard.me/) while the free features of NetGuard work properly
and I cannot fix the issue in a timely manner, you can get a refund.
In all other cases there is no refund possible.
I take my responsibility as seller to deliver what has been promised and I expect that you to take responsibility for informing yourself of what you are buying.

<a name="FAQ47"></a>
**(47) Why are there in application advertisements?**

Developing NetGuard was quite a challenge and [really a lot of work](https://www.openhub.net/p/netguard/estimated_cost), but fun to do.
A good product deserves good support, which means in practice that I am spending 30-60 minutes each and every day answering questions and solving problems.
Just about 1 in 1000 downloaders purchase any of the pro features, so support is basically one way.
This is not maintainable in the long run and this is why advertisements were added.
Purchasing any of the pro features will completely disable advertisements and help keep the project going.

<a name="FAQ48"></a>
**(48) Why are some domain names blocked while they are set to be allowed?**

NetGuard blocks traffic based on the IP addresses an application is trying to connect to.
If more than one domain name is on the same IP, they cannot be distinguished.
If you set different rules for 2 domains which resolve to the same IP, both will be blocked.

Thanks @[pulser](https://github.com/pulser/)

Another potential problem is that Android doesn't honor the DNS TTL value and applies its own caching rules.
This could result in NetGuard too early or too late purging a DNS record from its own cache,
resulting in not recognizing an IP address or recognizing a wrong IP address.
You can try to workaround this by changing the DNS TTL value setting of NetGuard.
This value is used as a minimum DNS TTL value in an attempt to mimick the behavior of Android.

<a name="FAQ49"></a>
**(49) Does NetGuard encrypt my internet traffic / hide my IP address?**

NetGuard is a firewall application that filters internet traffic on your device (see also [this question](#FAQ6)),
so it is not meant to and does not encrypt your internet traffic
and it is not meant to and does not hide your IP address.

<a name="FAQ50"></a>
**(50) Will NetGuard automatically start on boot?**

Yes, NetGuard will automatically be started on boot if you powered off your device with NetGuard enabled.

<a name="FAQ51"></a>
**(51) NetGuard blocks all internet traffic!**

Make sure you have put NetGuard on the doze exception list (Android 6 Marshmallow or later)
and that Android allows NetGuard to use the internet on the background.

Make sure you are not running NetGuard in whitelist mode (check the NetGuard default settings).

Some Android versions contain a bug resulting in all internet traffic being blocked.
Mostly you can workaround this bug by enabling filtering in the advanced NetGuard settings.

<a name="FAQ52"></a>
**(52) What is lockdown mode?**

In lockdown mode all traffic for all applictions will be blocked,
except for applications with the condition '*Allow in lockdown mode*' enabled.
You can use this mode to limit battery usage or network usage
for example when your battery is almost empty or when your data bundel is almost used.
Note that system applications will only be blocked in this mode
when managing system applications is enabled in the advanced settings.

You can enable/disable lockdown mode in the main menu, using a widget or using a settings tile (Android 7 Nougat or later).

<a name="FAQ53"></a>
**(53) The translation in my language is missing / incorrect / incomplete!**

You can contribute translations [here](https://crowdin.com/project/netguard) (registration is free).
If your language is missing, please contact me to have it added.

<a name="FAQ54"></a>
**(54) How to tunnel all TCP connections through the Tor network?**

First, install [Orbot](market://details?id=org.torproject.android), the Android client for Tor,
run it, press _Start_, while it connects open its _Settings_ and make sure it's setup to auto-start
on device start.

In NetGuard's _Network options_ enable _Subnet routing_ and in _Advanced options_ toggle on
_Use SOCKS5 proxy_ with address 127.0.0.1 and port as 9050 (this is the default port, if you changed
this in Orbot make the adjustment here also).

This should be enough, if testing fails (eg. no connection at all) you can open the app details
for Orbot, uncheck _Apply rules and conditions_ and retry.

How to test: open Firefox (or another non-proxy enabled browser) to the address https://ipleak.net/
and you should see a different IP address from your regular one, and below in the _Tor Exit Node_
field something else besides _Unknown_.

**Be aware** that all the other Tor caveats (https://www.torproject.org/docs/faq.html.en) still apply,
like having the Tor network unreacheable, your activity actively monitored/targeted in your country,
online services (eg. Gmail, Google Play store) failing to login or being forced to solve endless capchas
when accessing sites that use Cloudflare's CDN services.

**(55) Android's Data usage says Netguard sent 900MB, but ISP said only 100MB.**

Because netguard filter everything, including blocked packets.
From version x.y, Netguard will cut the internet connection for you like "Data usage" provides.
Pro feature.
You can set 3 values:
total '50M'B warning
'90M'B limit

**(56) "Noroot Data Firewall" app have speed limit. Can netguard do that?**

Yes, as a pro feature.



<br />

**NetGuard is supported for phones and tablets only, so not for other device types like on a television or in a car.**

**If you didn't find the answer to your question, you can ask your questions [in this forum](http://forum.xda-developers.com/showthread.php?t=3233012) or contact me by using [this contact form](https://contact.faircode.eu/)**.
