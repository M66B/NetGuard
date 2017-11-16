Ad Blocking with NetGuard
-------------------------

Instructions (you need to follow **all** the steps):

1. Download/install the latest NetGuard version [from GitHub](https://github.com/M66B/NetGuard/releases)
1. Enable the setting *'Filter traffic'* in the Advanced options (three dot menu > Settings > Advanced options > Filter traffic; default is disabled except always enabled in Android 5.0 and earlier)
1. Enable the setting *'Block domain names'* in the Advanced options (three dot menu > Settings > Advanced options > Block domain names; default is enabled)
1. Import or download [a hosts file](https://en.wikipedia.org/wiki/Hosts_(file)) using the NetGuard backup settings (three dot menu > Settings > Backup > Download hosts file)
1. Disable browser compression (in Chrome: three dot menu > Settings > Data Saver > Off)
1. Wait at least 10 minutes to let the Android DNS cache time out
1. Test to see if ad blocking works by opening [this page](http://www.netguard.me/test)
1. Enjoy ad blocking, but don't forget to support application developers and website authors in other ways

<br />

Troubleshooting:

Because of routing bugs, some devices/Android versions require:

* the advanced option *Manage system applications* to be enabled and/or
* the network option *Subnet routing* to be disabled and/or
* two (not just one) custom DNS server addresses to be set in the advanced options

<br />

Note that:

* applications, like web browsers, may cache data, so you may need to clear caches
* applications, browsers mostly, that have a *"data saver"*-like feature that proxies requests through their servers (eg. Opera w/ Turbo, Opera Max, Puffin, Chrome w/ data saver, UC Browser, Yandex w/ Turbo, Apus Browser, KK Browser, Onavo Extend, Maxthon) will not have ads blocked as NetGuard cannot see those domain requests
* YouTube ads are not domain-based, and thus cannot be blocked with NetGuard
* NetGuard ignores the IP addresses in the hosts file, because it does not route blocked domains to localhost
* NetGuard does not concatenate hosts files, so you will have to use a source which does this for you or do it yourself
* When NetGuard imports the hosts file, it automatically discards any duplicates entries, so duplicate entries are not a problem and have no performance impact after the file is imported
* you can check the number of hosts (domains) imported by pulling the NetGuard notification down using two fingers if your version of Android supports that functionality
* wildcards are not supported due to performance and battery usage reasons
* **ad blocking is provided as-is**, see also [here](https://forum.xda-developers.com/showpost.php?p=71805655&postcount=4668)
* **ad blocking is not available when NetGuard was installed from the Google Play store!** (disable automatic updates of NetGuard in the Play store application)

<br />

The NetGuard version from GitHub:

* is signed with the same signature as the version from the Google Play store, so any purchases will be restored
* will automatically notify you if there are updates available via GitHub (this can be switched off in NetGuard's settings)

<br />

Which hosts (ad servers) will be blocked depends on the hosts file being used.
NetGuard provides the [StevenBlack hosts file](https://github.com/StevenBlack/hosts) download with the following additions:

* reports.crashlytics.com
* settings.crashlytics.com
* e.crashlytics.com
* test.netguard.me

<br />

Automation:

You can automatically download a hosts file by sending this service intent with your favorite automation tool, like Tasker:

`eu.faircode.netguard.DOWNLOAD_HOSTS_FILE`

For example using [adb](https://developer.android.com/studio/command-line/adb.html) from the command line:

`adb shell am startservice -a eu.faircode.netguard.DOWNLOAD_HOSTS_FILE`

<br />

Apart from using a hosts file, you can block most in-app ads by blocking this address in the access list of Google Play services:

*googleads.g.doubleclick.net/443*

You'll need to enable filtering and (temporarily) logging for this (you can do this by using the *Configure* button; check both options)
and you'll need to wait until the address appears (you can speed this up by opening some apps with in-app ads).
Note that ads are likely being cached, so this may not take effect immediately.

<br />

An alternate way to block advertisements is by using special DNS servers, like these:

* [AdGuard DNS](https://adguard.com/en/adguard-dns/overview.html) - Free
* [Alternate DNS](https://alternate-dns.com/) - 14 day free trial
* [NoAd](https://noad.zone/) - Not working as of 2017 June 03

Be sure to read the privacy policies of these services as they might log your DNS requests.

You can set DNS server addresses for all connection types in NetGuard's *Advanced options*.
Note that when you set two DNS server addresses, the default (operating system/network provider) DNS servers will not be used anymore.

Feel free to let me know about other servers or request to add them in alphabetic order by doing a pull request.

<br />

**Please do not mention this feature in Google Play store comments, since Google does not allow ad blocking applications in the Google Play store.**
