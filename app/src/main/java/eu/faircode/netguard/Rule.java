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
import android.text.TextUtils;
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
    public boolean system;
    public boolean internet;
    public boolean enabled;
    public Intent intent;

    public boolean wifi_default;
    public boolean other_default;
    public boolean screen_wifi_default;
    public boolean screen_other_default;
    public boolean roaming_default;

    public boolean wifi_blocked;
    public boolean other_blocked;
    public boolean screen_wifi;
    public boolean screen_other;
    public boolean roaming;

    public String[] related = null;

    public float upspeed;
    public float downspeed;
    public float totalbytes;

    public boolean changed;

    public boolean expanded = false;

    private Rule(PackageInfo info, Context context) {
        PackageManager pm = context.getPackageManager();

        this.info = info;
        if (info.applicationInfo.uid == 0) {
            this.name = context.getString(R.string.title_root);
            this.system = true;
            this.internet = true;
            this.enabled = true;
            this.intent = null;
        } else if (info.applicationInfo.uid == 1013) {
            this.name = context.getString(R.string.title_mediaserver);
            this.system = true;
            this.internet = true;
            this.enabled = true;
            this.intent = null;
        } else {
            this.name = info.applicationInfo.loadLabel(pm).toString();
            this.system = Util.isSystem(info.packageName, context);
            this.internet = Util.hasInternet(info.packageName, context);

            int setting;
            try {
                setting = pm.getApplicationEnabledSetting(info.packageName);
            } catch (IllegalArgumentException ex) {
                setting = PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;
                Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
            if (setting == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT)
                this.enabled = info.applicationInfo.enabled;
            else
                this.enabled = (setting == PackageManager.COMPONENT_ENABLED_STATE_ENABLED);

            this.intent = pm.getLaunchIntentForPackage(info.packageName);
        }
    }

    public static List<Rule> getRules(boolean all, String tag, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences wifi = context.getSharedPreferences("wifi", Context.MODE_PRIVATE);
        SharedPreferences other = context.getSharedPreferences("other", Context.MODE_PRIVATE);
        SharedPreferences screen_wifi = context.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE);
        SharedPreferences screen_other = context.getSharedPreferences("screen_other", Context.MODE_PRIVATE);
        SharedPreferences roaming = context.getSharedPreferences("roaming", Context.MODE_PRIVATE);

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
                        Log.d(tag, "Wifi " + pkg + " blocked=" + pblocked);

                    } else if ("other".equals(xml.getName())) {
                        String pkg = xml.getAttributeValue(null, "package");
                        boolean pblocked = xml.getAttributeBooleanValue(null, "blocked", false);
                        boolean proaming = xml.getAttributeBooleanValue(null, "roaming", default_roaming);
                        pre_other_blocked.put(pkg, pblocked);
                        pre_roaming.put(pkg, proaming);
                        Log.d(tag, "Other " + pkg + " blocked=" + pblocked + " roaming=" + proaming);

                    } else if ("relation".equals(xml.getName())) {
                        String pkg = xml.getAttributeValue(null, "package");
                        String[] rel = xml.getAttributeValue(null, "related").split(",");
                        pre_related.put(pkg, rel);
                        Log.d(tag, "Relation " + pkg + " related=" + TextUtils.join(",", rel));

                    } else if ("type".equals(xml.getName())) {
                        String pkg = xml.getAttributeValue(null, "package");
                        boolean system = xml.getAttributeBooleanValue(null, "system", true);
                        pre_system.put(pkg, system);
                        Log.d(tag, "Type " + pkg + " system=" + system);
                    }


                eventType = xml.next();
            }
        } catch (Throwable ex) {
            Log.e(tag, ex.toString() + "\n" + Log.getStackTraceString(ex));
            Util.sendCrashReport(ex, context);
        }

        // Build rule list
        List<Rule> listRules = new ArrayList<>();

        PackageManager pm = context.getPackageManager();
        List<PackageInfo> listPI = pm.getInstalledPackages(0);

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

        for (PackageInfo info : listPI) {
            Rule rule = new Rule(info, context);

            if (pre_system.containsKey(info.packageName))
                rule.system = pre_system.get(info.packageName);

            if (all ||
                    ((rule.system ? show_system : show_user) &&
                            (show_nointernet || rule.internet) &&
                            (show_disabled || rule.enabled) &&
                            info.applicationInfo.uid != Process.myUid())) {

                if (info.applicationInfo.uid == Process.myUid()) {
                    // Internet access is needed to resolve host names
                    rule.wifi_default = false;
                    rule.other_default = false;
                    rule.screen_wifi_default = false;
                    rule.screen_other_default = false;
                    rule.roaming_default = false;

                    rule.wifi_blocked = false;
                    rule.other_blocked = false;
                    rule.screen_wifi = false;
                    rule.screen_other = false;
                    rule.roaming = false;
                } else {
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
                }

                List<String> listPkg = new ArrayList<>();
                if (pre_related.containsKey(info.packageName))
                    listPkg.addAll(Arrays.asList(pre_related.get(info.packageName)));
                String[] pkgs = pm.getPackagesForUid(info.applicationInfo.uid);
                if (pkgs != null)
                    listPkg.addAll(Arrays.asList(pkgs));
                listPkg.remove(info.packageName);
                rule.related = listPkg.toArray(new String[0]);

                long up = TrafficStats.getUidTxBytes(rule.info.applicationInfo.uid);
                long down = TrafficStats.getUidRxBytes(rule.info.applicationInfo.uid);
                rule.totalbytes = up + down;
                rule.upspeed = (float) up * 24 * 3600 * 1000 / 1024f / 1024f / now;
                rule.downspeed = (float) down * 24 * 3600 * 1000 / 1024f / 1024f / now;

                rule.updateChanged(default_wifi, default_other, default_roaming);

                listRules.add(rule);
            }
        }

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
                    else
                        return 0;
                }
            });
        else
            Collections.sort(listRules, new Comparator<Rule>() {
                @Override
                public int compare(Rule rule, Rule other) {
                    if (rule.changed == other.changed) {
                        Collator collator = Collator.getInstance(Locale.getDefault());
                        collator.setStrength(Collator.SECONDARY); // Case sensitive, process accents etc
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
                ((!other_blocked || screen_other) && roaming != default_roaming));
    }

    public void updateChanged(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean default_wifi = prefs.getBoolean("whitelist_wifi", true);
        boolean default_other = prefs.getBoolean("whitelist_other", true);
        boolean default_roaming = prefs.getBoolean("whitelist_roaming", true);
        updateChanged(default_wifi, default_other, default_roaming);
    }
}
