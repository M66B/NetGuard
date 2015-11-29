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

    Copyright 2015 by Marcel Bokhorst (M66B)
*/

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.XmlResourceParser;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import android.util.Log;

import org.xmlpull.v1.XmlPullParser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Rule implements Comparable<Rule> {
    private static final String TAG = "NetGuard.Rule";

    public PackageInfo info;
    public String name;
    public boolean system;
    public boolean internet;
    public boolean disabled;

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

    public boolean changed;

    public Intent intent;

    public boolean expanded = false;

    private Rule(PackageInfo info, Context context) {
        PackageManager pm = context.getPackageManager();

        this.info = info;
        this.name = info.applicationInfo.loadLabel(pm).toString();

        this.internet = (pm.checkPermission("android.permission.INTERNET", info.packageName) == PackageManager.PERMISSION_GRANTED);

        int setting;
        try {
            setting = pm.getApplicationEnabledSetting(info.packageName);
        } catch (IllegalArgumentException ex) {
            setting = PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;
            Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
        if (setting == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT)
            this.disabled = !info.applicationInfo.enabled;
        else
            this.disabled = (setting != PackageManager.COMPONENT_ENABLED_STATE_ENABLED);

        this.intent = pm.getLaunchIntentForPackage(info.packageName);
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

        // Get predefined rules
        Map<String, Boolean> pre_blocked = new HashMap<>();
        Map<String, Boolean> pre_roaming = new HashMap<>();
        Map<String, String[]> pre_related = new HashMap<>();
        try {
            XmlResourceParser xml = context.getResources().getXml(R.xml.predefined);
            int eventType = xml.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                if (eventType == XmlPullParser.START_TAG)
                    if ("rule".equals(xml.getName())) {
                        String pkg = xml.getAttributeValue(null, "package");
                        boolean pblocked = xml.getAttributeBooleanValue(null, "blocked", false);
                        boolean proaming = xml.getAttributeBooleanValue(null, "roaming", default_roaming);
                        pre_blocked.put(pkg, pblocked);
                        pre_roaming.put(pkg, proaming);
                        Log.d(tag, "Predefined " + pkg + " blocked=" + pblocked + " roaming=" + proaming);

                    } else if ("relation".equals(xml.getName())) {
                        String pkg = xml.getAttributeValue(null, "package");
                        String[] rel = xml.getAttributeValue(null, "related").split(",");
                        pre_related.put(pkg, rel);

                        Log.d(tag, "Relation " + pkg + " related=" + TextUtils.join(",", rel));
                    }

                eventType = xml.next();
            }
        } catch (Throwable ex) {
            Log.e(tag, ex.toString() + "\n" + Log.getStackTraceString(ex));
            Util.sendCrashReport(ex, context);
        }

        // Build rule list
        List<Rule> listRules = new ArrayList<>();
        for (PackageInfo info : context.getPackageManager().getInstalledPackages(0)) {
            boolean system = ((info.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
            if (!system || manage_system || all) {
                Rule rule = new Rule(info, context);

                rule.system = system;

                rule.wifi_default = (pre_blocked.containsKey(info.packageName) ? pre_blocked.get(info.packageName) : default_wifi);
                rule.other_default = (pre_blocked.containsKey(info.packageName) ? pre_blocked.get(info.packageName) : default_other);
                rule.screen_wifi_default = default_screen_wifi;
                rule.screen_other_default = default_screen_other;
                rule.roaming_default = (pre_roaming.containsKey(info.packageName) ? pre_roaming.get(info.packageName) : default_roaming);

                rule.wifi_blocked = (system && !manage_system ? false : wifi.getBoolean(info.packageName, rule.wifi_default));
                rule.other_blocked = (system && !manage_system ? false : other.getBoolean(info.packageName, rule.other_default));
                rule.screen_wifi = screen_wifi.getBoolean(info.packageName, rule.screen_wifi_default);
                rule.screen_other = screen_other.getBoolean(info.packageName, rule.screen_other_default);
                rule.roaming = roaming.getBoolean(info.packageName, rule.roaming_default);

                if (pre_related.containsKey(info.packageName))
                    rule.related = pre_related.get(info.packageName);

                rule.updateChanged(default_wifi, default_other, default_roaming);

                listRules.add(rule);
            }
        }

        // Sort rule list
        Collections.sort(listRules);

        return listRules;
    }

    private void updateChanged(boolean default_wifi, boolean default_other, boolean default_roaming) {
        changed = (wifi_blocked != default_wifi ||
                other_blocked != default_other ||
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

    @Override
    public int compareTo(Rule other) {
        if (changed == other.changed) {
            int i = name.compareToIgnoreCase(other.name);
            return (i == 0 ? info.packageName.compareTo(other.info.packageName) : i);
        }
        return (changed ? -1 : 1);
    }
}
