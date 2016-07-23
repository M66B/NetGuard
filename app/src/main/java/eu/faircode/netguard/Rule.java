package eu.faircode.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2016 by Marcel Bokhorst (M66B)
*/

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.XmlResourceParser;
import android.net.TrafficStats;
import android.os.Build;
import android.os.Process;
import android.os.SystemClock;
import android.preference.PreferenceManager;
import android.util.Log;

import org.xmlpull.v1.XmlPullParser;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class Rule {
    private static final String TAG = "NetGuard.Rule";

    public PackageInfo info;
    public String name;
    public String description;
    public boolean system;
    public boolean internet;
    public boolean enabled;
    public Intent intent;
    public boolean pkg = true;

    public boolean wifi_default = false;
    public boolean other_default = false;
    public boolean screen_wifi_default = false;
    public boolean screen_other_default = false;
    public boolean roaming_default = false;

    public boolean wifi_blocked = false;
    public boolean other_blocked = false;
    public boolean screen_wifi = false;
    public boolean screen_other = false;
    public boolean roaming = false;

    public boolean apply = true;
    public boolean notify = true;

    public boolean relateduids = false;
    public String[] related = null;

    public float upspeed;
    public float downspeed;
    public float totalbytes;

    public boolean changed;

    public boolean expanded = false;

    private static List<PackageInfo> cachePackageInfo = null;
    private static Map<PackageInfo, String> cacheLabel = new HashMap<>();
    private static Map<PackageInfo, String> cacheDescription = new HashMap<>();
    private static Map<String, Boolean> cacheSystem = new HashMap<>();
    private static Map<String, Boolean> cacheInternet = new HashMap<>();
    private static Map<PackageInfo, Boolean> cacheEnabled = new HashMap<>();
    private static Map<String, Intent> cacheIntent = new HashMap<>();
    private static Map<Integer, String[]> cachePackages = new HashMap<>();

    private static List<PackageInfo> getPackages(Context context) {
        synchronized (context.getApplicationContext()) {
            if (cachePackageInfo == null) {
                PackageManager pm = context.getPackageManager();
                cachePackageInfo = pm.getInstalledPackages(0);
            }
            return new ArrayList<>(cachePackageInfo);
        }
    }

    private static String getLabel(PackageInfo info, Context context) {
        synchronized (context.getApplicationContext()) {
            if (!cacheLabel.containsKey(info)) {
                PackageManager pm = context.getPackageManager();
                cacheLabel.put(info, info.applicationInfo.loadLabel(pm).toString());
            }
            return cacheLabel.get(info);
        }
    }

    private static String getDescription(PackageInfo info, Context context) {
        synchronized (context.getApplicationContext()) {
            if (!cacheDescription.containsKey(info)) {
                PackageManager pm = context.getPackageManager();
                CharSequence description = info.applicationInfo.loadDescription(pm);
                cacheDescription.put(info, description == null ? null : description.toString());
            }
            return cacheDescription.get(info);
        }
    }

    private static boolean isSystem(String packageName, Context context) {
        synchronized (context.getApplicationContext()) {
            if (!cacheSystem.containsKey(packageName))
                cacheSystem.put(packageName, Util.isSystem(packageName, context));
            return cacheSystem.get(packageName);
        }
    }

    private static boolean hasInternet(String packageName, Context context) {
        synchronized (context.getApplicationContext()) {
            if (!cacheInternet.containsKey(packageName))
                cacheInternet.put(packageName, Util.hasInternet(packageName, context));
            return cacheInternet.get(packageName);
        }
    }

    private static boolean isEnabled(PackageInfo info, Context context) {
        synchronized (context.getApplicationContext()) {
            if (!cacheEnabled.containsKey(info))
                cacheEnabled.put(info, Util.isEnabled(info, context));
            return cacheEnabled.get(info);
        }
    }

    private static Intent getIntent(String packageName, Context context) {
        synchronized (context.getApplicationContext()) {
            if (!cacheIntent.containsKey(packageName))
                cacheIntent.put(packageName, context.getPackageManager().getLaunchIntentForPackage(packageName));
            return cacheIntent.get(packageName);
        }
    }

    private static String[] getPackages(int uid, Context context) {
        synchronized (context.getApplicationContext()) {
            if (!cachePackages.containsKey(uid))
                cachePackages.put(uid, context.getPackageManager().getPackagesForUid(uid));
            return cachePackages.get(uid);
        }
    }

    public static void clearCache(Context context) {
        Log.i(TAG, "Clearing cache");
        synchronized (context.getApplicationContext()) {
            cachePackageInfo = null;
            cacheLabel.clear();
            cacheDescription.clear();
            cacheSystem.clear();
            cacheInternet.clear();
            cacheEnabled.clear();
            cacheIntent.clear();
            cachePackages.clear();
        }
    }

    private Rule(PackageInfo info, Context context) {
        this.info = info;
        if (info.applicationInfo.uid == 0) {
            this.name = context.getString(R.string.title_root);
            this.description = null;
            this.system = true;
            this.internet = true;
            this.enabled = true;
            this.intent = null;
            this.pkg = false;
        } else if (info.applicationInfo.uid == 1013) {
            this.name = context.getString(R.string.title_mediaserver);
            this.description = null;
            this.system = true;
            this.internet = true;
            this.enabled = true;
            this.intent = null;
            this.pkg = false;
        } else if (info.applicationInfo.uid == 9999) {
            this.name = context.getString(R.string.title_nobody);
            this.description = null;
            this.system = true;
            this.internet = true;
            this.enabled = true;
            this.intent = null;
            this.pkg = false;
        } else {
            this.name = getLabel(info, context);
            this.description = getDescription(info, context);
            this.system = isSystem(info.packageName, context);
            this.internet = hasInternet(info.packageName, context);
            this.enabled = isEnabled(info, context);
            this.intent = getIntent(info.packageName, context);
        }
    }

    public static List<Rule> getRules(final boolean all, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences wifi = context.getSharedPreferences("wifi", Context.MODE_PRIVATE);
        SharedPreferences other = context.getSharedPreferences("other", Context.MODE_PRIVATE);
        SharedPreferences screen_wifi = context.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE);
        SharedPreferences screen_other = context.getSharedPreferences("screen_other", Context.MODE_PRIVATE);
        SharedPreferences roaming = context.getSharedPreferences("roaming", Context.MODE_PRIVATE);
        SharedPreferences apply = context.getSharedPreferences("apply", Context.MODE_PRIVATE);
        SharedPreferences notify = context.getSharedPreferences("notify", Context.MODE_PRIVATE);

        // Get settings
        boolean default_wifi = prefs.getBoolean("whitelist_wifi", true);
        boolean default_other = prefs.getBoolean("whitelist_other", true);
        boolean default_screen_wifi = prefs.getBoolean("screen_wifi", true);
        boolean default_screen_other = prefs.getBoolean("screen_other", true);
        boolean default_roaming = prefs.getBoolean("whitelist_roaming", true);
        boolean manage_system = prefs.getBoolean("manage_system", false);
        boolean show_user = prefs.getBoolean("show_user", true);
        boolean show_system = prefs.getBoolean("show_system", false);
        boolean show_nointernet = prefs.getBoolean("show_nointernet", true);
        boolean show_disabled = prefs.getBoolean("show_disabled", true);

        long now = SystemClock.elapsedRealtime();

        // Get predefined rules
        Map<String, Boolean> pre_wifi_blocked = new HashMap<>();
        Map<String, Boolean> pre_other_blocked = new HashMap<>();
        Map<String, Boolean> pre_roaming = new HashMap<>();
        Map<String, String[]> pre_related = new HashMap<>();
        Map<String, Boolean> pre_system = new HashMap<>();
        try {
            XmlResourceParser xml = context.getResources().getXml(R.xml.predefined);
            int eventType = xml.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                if (eventType == XmlPullParser.START_TAG)
                    if ("wifi".equals(xml.getName())) {
                        String pkg = xml.getAttributeValue(null, "package");
                        boolean pblocked = xml.getAttributeBooleanValue(null, "blocked", false);
                        pre_wifi_blocked.put(pkg, pblocked);

                    } else if ("other".equals(xml.getName())) {
                        String pkg = xml.getAttributeValue(null, "package");
                        boolean pblocked = xml.getAttributeBooleanValue(null, "blocked", false);
                        boolean proaming = xml.getAttributeBooleanValue(null, "roaming", default_roaming);
                        pre_other_blocked.put(pkg, pblocked);
                        pre_roaming.put(pkg, proaming);

                    } else if ("relation".equals(xml.getName())) {
                        String pkg = xml.getAttributeValue(null, "package");
                        String[] rel = xml.getAttributeValue(null, "related").split(",");
                        pre_related.put(pkg, rel);

                    } else if ("type".equals(xml.getName())) {
                        String pkg = xml.getAttributeValue(null, "package");
                        boolean system = xml.getAttributeBooleanValue(null, "system", true);
                        pre_system.put(pkg, system);
                    }


                eventType = xml.next();
            }
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        // Build rule list
        List<Rule> listRules = new ArrayList<>();
        List<PackageInfo> listPI = getPackages(context);

        // Add root
        PackageInfo root = new PackageInfo();
        root.packageName = "root";
        root.versionCode = Build.VERSION.SDK_INT;
        root.versionName = Build.VERSION.RELEASE;
        root.applicationInfo = new ApplicationInfo();
        root.applicationInfo.uid = 0;
        root.applicationInfo.icon = 0;
        listPI.add(root);

        // Add mediaserver
        PackageInfo media = new PackageInfo();
        media.packageName = "android.media";
        media.versionCode = Build.VERSION.SDK_INT;
        media.versionName = Build.VERSION.RELEASE;
        media.applicationInfo = new ApplicationInfo();
        media.applicationInfo.uid = 1013;
        media.applicationInfo.icon = 0;
        listPI.add(media);

        // Add nobody
        PackageInfo nobody = new PackageInfo();
        nobody.packageName = "nobody";
        nobody.versionCode = Build.VERSION.SDK_INT;
        nobody.versionName = Build.VERSION.RELEASE;
        nobody.applicationInfo = new ApplicationInfo();
        nobody.applicationInfo.uid = 9999;
        nobody.applicationInfo.icon = 0;
        listPI.add(nobody);

        for (PackageInfo info : listPI)
            try {
                Rule rule = new Rule(info, context);

                if (pre_system.containsKey(info.packageName))
                    rule.system = pre_system.get(info.packageName);
                if (info.applicationInfo.uid == Process.myUid())
                    rule.system = true;

                if (all ||
                        ((rule.system ? show_system : show_user) &&
                                (show_nointernet || rule.internet) &&
                                (show_disabled || rule.enabled))) {

                    rule.wifi_default = (pre_wifi_blocked.containsKey(info.packageName) ? pre_wifi_blocked.get(info.packageName) : default_wifi);
                    rule.other_default = (pre_other_blocked.containsKey(info.packageName) ? pre_other_blocked.get(info.packageName) : default_other);
                    rule.screen_wifi_default = default_screen_wifi;
                    rule.screen_other_default = default_screen_other;
                    rule.roaming_default = (pre_roaming.containsKey(info.packageName) ? pre_roaming.get(info.packageName) : default_roaming);

                    rule.wifi_blocked = (!(rule.system && !manage_system) && wifi.getBoolean(info.packageName, rule.wifi_default));
                    rule.other_blocked = (!(rule.system && !manage_system) && other.getBoolean(info.packageName, rule.other_default));
                    rule.screen_wifi = screen_wifi.getBoolean(info.packageName, rule.screen_wifi_default);
                    rule.screen_other = screen_other.getBoolean(info.packageName, rule.screen_other_default);
                    rule.roaming = roaming.getBoolean(info.packageName, rule.roaming_default);

                    rule.apply = apply.getBoolean(info.packageName, true);
                    rule.notify = notify.getBoolean(info.packageName, true);

                    // Related packages
                    List<String> listPkg = new ArrayList<>();
                    if (pre_related.containsKey(info.packageName))
                        listPkg.addAll(Arrays.asList(pre_related.get(info.packageName)));
                    String[] pkgs = getPackages(info.applicationInfo.uid, context);
                    if (pkgs != null && pkgs.length > 1) {
                        rule.relateduids = true;
                        listPkg.addAll(Arrays.asList(pkgs));
                        listPkg.remove(info.packageName);
                    }
                    rule.related = listPkg.toArray(new String[0]);

                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
                        long up = TrafficStats.getUidTxBytes(rule.info.applicationInfo.uid);
                        long down = TrafficStats.getUidRxBytes(rule.info.applicationInfo.uid);
                        rule.totalbytes = up + down;
                        rule.upspeed = (float) up * 24 * 3600 * 1000 / 1024f / 1024f / now;
                        rule.downspeed = (float) down * 24 * 3600 * 1000 / 1024f / 1024f / now;
                    } else {
                        rule.upspeed = 0;
                        rule.downspeed = 0;
                    }

                    rule.updateChanged(default_wifi, default_other, default_roaming);

                    listRules.add(rule);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

        final Collator collator = Collator.getInstance(Locale.getDefault());
        collator.setStrength(Collator.SECONDARY); // Case insensitive, process accents etc

        // Sort rule list
        String sort = prefs.getString("sort", "name");
        if ("data".equals(sort))
            Collections.sort(listRules, new Comparator<Rule>() {
                @Override
                public int compare(Rule rule, Rule other) {
                    if (rule.totalbytes < other.totalbytes)
                        return 1;
                    else if (rule.totalbytes > other.totalbytes)
                        return -1;
                    else {
                        int i = collator.compare(rule.name, other.name);
                        return (i == 0 ? rule.info.packageName.compareTo(other.info.packageName) : i);
                    }
                }
            });
        else if ("uid".equals(sort))
            Collections.sort(listRules, new Comparator<Rule>() {
                @Override
                public int compare(Rule rule, Rule other) {
                    if (rule.info.applicationInfo.uid < other.info.applicationInfo.uid)
                        return -1;
                    else if (rule.info.applicationInfo.uid > other.info.applicationInfo.uid)
                        return 1;
                    else {
                        int i = collator.compare(rule.name, other.name);
                        return (i == 0 ? rule.info.packageName.compareTo(other.info.packageName) : i);
                    }
                }
            });
        else
            Collections.sort(listRules, new Comparator<Rule>() {
                @Override
                public int compare(Rule rule, Rule other) {
                    if (all || rule.changed == other.changed) {
                        int i = collator.compare(rule.name, other.name);
                        return (i == 0 ? rule.info.packageName.compareTo(other.info.packageName) : i);
                    }
                    return (rule.changed ? -1 : 1);
                }
            });

        return listRules;
    }

    private void updateChanged(boolean default_wifi, boolean default_other, boolean default_roaming) {
        changed = (wifi_blocked != default_wifi ||
                (other_blocked != default_other) ||
                (wifi_blocked && screen_wifi != screen_wifi_default) ||
                (other_blocked && screen_other != screen_other_default) ||
                ((!other_blocked || screen_other) && roaming != default_roaming) ||
                !apply);
    }

    public void updateChanged(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean default_wifi = prefs.getBoolean("whitelist_wifi", true);
        boolean default_other = prefs.getBoolean("whitelist_other", true);
        boolean default_roaming = prefs.getBoolean("whitelist_roaming", true);
        updateChanged(default_wifi, default_other, default_roaming);
    }

    @Override
    public String toString() {
        // This is used in the port forwarding dialog application selector
        return this.name;
    }
}
