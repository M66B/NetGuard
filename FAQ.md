NetGuard
========

Please scroll down if you want to ask a question, request a feature or report a bug.

Frequently Asked Questions (FAQ)
--------------------------------

<a name="FAQ0"></a>
**(0) How do I use NetGuard?**

* Enable the firewall using the switch in the action bar
* Allow/deny Wi-Fi/mobile internet access using the icons along the right side of the application list

You can use the settings menu to change from blacklist mode (allow all in *Settings* but block unwanted applications in list) to whitelist mode (block all in *Settings* but allow favorite applications in list).

* Orange = denied internet access
* Green = allowed internet access

<a name="FAQ1"></a>
**(1) Can NetGuard completely protect my privacy?**

No - nothing can completely protect your privacy.
NetGuard will do its best, but it is limited by the fact it must use the VPN service.
This is the trade-off required to make a firewall which does not require root access.
The firewall can only start when Android "allows" it to start,
so it will not offer protection during early boot-up (although your network may not be loaded at that time).
It will, however, be much better than nothing, especially if you are not rebooting often.

If you want to protect yourself more, you can (at least in theory) disable Wi-Fi and mobile data before rebooting,
and only enable them on reboot, after the firewall service has started (and the small key icon is visible in the status bar).

Thanks @[pulser](https://github.com/pulser/)

<a name="FAQ2"></a>
**(2)  Can I use another VPN application while using NetGuard**

If the VPN application is using the [VPN service](http://developer.android.com/reference/android/net/VpnService.html),
then no, because NetGuard needs to use this service. Android allows only one application at a time to use this service.

<a name="FAQ3"></a>
**(3) Can I use NetGuard on any Android version?**

No, the minimum required Android version is 5.0 (Lollipop)
because NetGuard uses the [addDisallowedApplication](http://developer.android.com/reference/android/net/VpnService.Builder.html#addDisallowedApplication(java.lang.String)) method.

<a name="FAQ4"></a>
**(4) Will NetGuard use extra battery power?**

No, unlike most of the similar closed source alternatives.

However, the network speed graph notification will use extra battery power.
This is why the notification is shown only when the screen is on.
You can decrease the update frequency using the settings to reduce the battery usage.

<a name="FAQ5"></a>
**(5) Can you add usage statistics?**<br />
**(5) Can you add popups to allow/block applications?**<br />
**(5) Can you add selective allowing/blocking applications/IP addresses?**

Unfortunately, this is not possible without using significant battery power
and adding complex code to do network translation from OSI layer 3 to layer 4
(and thus implementing a TCP/IP stack), which will inevitably introduce bugs as well.
This is how most (perhaps all) other no-root firewalls work.
NetGuard is unique, because it doesn't implement a TCP/IP stack, and is therefore both highly efficient and simple.

For more advanced use cases, rooting your device and using an iptables based firewall,
like [AFWall+](https://github.com/ukanth/afwall), might be a better option and will not sacrifice any battery power.

<a name="FAQ6"></a>
**(6) Will NetGuard send my internet traffic to an external (VPN) server?**

No. It cannot even do this because NetGuard does not even have *internet* permission.

<a name="FAQ7"></a>
**(7) Why are applications without internet permission shown?**

Internet permission can be granted with each application update without user consent.
By showing all applications, NetGuard allows you to control internet access even *before* such an update occurs.

<a name="FAQ8"></a>
**(8) What do I need to enable for the Google Play™ store app to work?**

You need 3 packages (applications) enabled (use search in NetGuard to find them quickly):

* com.android.vending
* com.google.android.gms
* com.android.providers.downloads

Since the Google Play™ store app has a tendency to check for updates or even download them all by itself (even if no account is associated),
one can keep it in check by enabling "*Allow when device in use*" for all 3 of these packages.
Click on the down arrow on the left side of an application name and check that option,
but leave the network icons set to red (hence blocked).The little human icon will appear for those packages.

<a name="FAQ9"></a>
**(9) Why is the VPN service being restarted?**

The VPN service will be restarted when you turn the screen on or off and when connectivity changes (Wi-Fi, mobile)
to apply the rules with the conditions '*Allow when screen is on*' and '*Block when roaming*'.

<a name="FAQ10"></a>
**(10) Will you provide a Tasker plug-in?**

If disabling NetGuard is allowed to Tasker, any application can disabled NetGuard too.
Allowing to disable a security application from other applications is not a good idea.

<a name="FAQ12"></a>
**(12) Can you add on demand asking to block/allow access?**

Besides that this requires questionable Android permissions,
it is not possible to implement this, given the way NetGuard works.
For more details, see [question 5](#FAQ5).

<a name="FAQ13"></a>
**(13) How can I remove the ongoing NetGuard entry in the notification screen?**

* Long click the NetGuard notification
* Tap the 'i' icon
* Depending on your device and/or ROMs manufacturer software customisations, you can be directed to either:
  * the **App Info** screen and you can uncheck '*Show notifications*' and agree to the next dialog
  * the **App Notifications** screen and you can toggle the '*Block*' slider to on

Note that, whether or not you get a dialog warning to agree upon, this operation will disable any warning notifications from NetGuard as well.

To read about the need for the notification in the first place, see [question 24](#FAQ24).

<a name="FAQ14"></a>
**(14) Why can't I select OK to approve the VPN connection request?**

There might be another application on top of the VPN connection request dialog.
Some known (screen dimming) applications which can cause this are *Lux Brightness*, *Night Mode* and *Twilight*.
To avoid this problem, at least temporary, close all applications and/or services which may be running in the background.

<a name="FAQ15"></a>
**(15) Why won't you support the F-Droid builds?**

Because F-Droid doesn't support reproducible builds.
Read [here](https://blog.torproject.org/blog/deterministic-builds-part-one-cyberwar-and-global-compromise) why this is important.

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

NetGuard requires at least Android 5.0, so it is not available in the Google Play™ store app for devices running older Android versions.

Some devices have an Android version with a bug in the services NetGuard depends upon.
These devices are blacklisted in the Google Play™ store app. Read about them in the [compatibility section](https://github.com/M66B/NetGuard#compatibility).

<a name="FAQ19"></a>
**(19) Why does aplication XYZ still have internet access?**

If you block internet access for an application, there is no way around it.
However, applications could access the internet through other applications, like Google Play services.
You can prevent this by blocking internet access for the other application as well.

<a name="FAQ20"></a>
**(20) Can I Greenify/hibernate NetGuard?**

No. [Greenifying](https://play.google.com/store/apps/details?id=com.oasisfeng.greenify)
or otherwise hibernating NetGuard will result in rules not being applied
when connectivity changes from Wi-Fi/mobile, screen on/off and roaming/not roaming.

<a name="FAQ21"></a>
**(21) Does doze mode affect NetGuard?**

I am not sure, because the [doze mode documentation](http://developer.android.com/training/monitoring-device-state/doze-standby.html)
is not clear if broadcast receivers will be disabled in doze mode.
If broadcast receivers are being disabled, then the rules might not be reloaded at the correct time or not at all
when connectivity changes from Wi-Fi to mobile or the other way around.
To be sure you can disable battery optimizations for NetGuard manually like this:

```
Android settings > Battery > three dot menu > Battery optimizations > Dropdown > All apps > NetGuard > Don't optimize > Done
```

This cannot be done from the application, because NetGuard is not an application type allowed to do this.

<a name="FAQ22"></a>
**(22) Can I tether / use Wi-Fi calling while using NetGuard?**

Due to a bug in Android this is not possible.
See [here](https://github.com/M66B/NetGuard/issues/42) for more information.

<a name="FAQ24"></a>
**(24) Can you remove the notification from the status bar?**

Android can kill background services at any time.
This can only be prevented by turning a background service into a foreground service.
Android requires an ongoing notification for all foreground services
to make you aware of potential battery ussage.
So, the notification cannot be removed without causing instability.
However, the notification is being marked as low priority,
which should result in moving it to the bottom of the list.

<a name="FAQ25"></a>
**(25) Can you add a 'select all'?**

There is no need for a select all function,
because you can switch from black list to white list mode using the settings.
See also [question 0](#FAQ0).

<br />

**If you didn't found the answer to your question, you can ask your questions [here](http://forum.xda-developers.com/showthread.php?t=3233012)**.

If you want to request a new feature or want to report a bug, please [create an issue on GitHub](https://github.com/M66B/NetGuard/issues/new).
