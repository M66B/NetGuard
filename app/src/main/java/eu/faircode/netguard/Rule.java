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
import android.graphics.drawable.Drawable;
import android.preference.PreferenceManager;
import android.util.Log;

import org.xmlpull.v1.XmlPullParser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Rule implements Comparable<Rule> {
    public PackageInfo info;
    public String name;
    public boolean system;
    public boolean disabled;

    public boolean wifi_default;
    public boolean other_default;
    public boolean unused_default;
    public boolean roaming_default;

    public boolean wifi_blocked;
    public boolean other_blocked;
    public boolean unused;
    public boolean roaming;

    public boolean changed;

    public Intent intent;

    public boolean attributes = false;

    private Rule(PackageInfo info, Context context) {
        PackageManager pm = context.getPackageManager();

        this.info = info;
        this.name = info.applicationInfo.loadLabel(pm).toString();

        int setting = pm.getApplicationEnabledSetting(info.packageName);
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
        SharedPreferences unused = context.getSharedPreferences("unused", Context.MODE_PRIVATE);
        SharedPreferences roaming = context.getSharedPreferences("roaming", Context.MODE_PRIVATE);

        // Get settings
        boolean whitelist_wifi = prefs.getBoolean("whitelist_wifi", true);
        boolean whitelist_other = prefs.getBoolean("whitelist_other", true);
        boolean whitelist_roaming = prefs.getBoolean("whitelist_roaming", true);
        boolean manage_system = prefs.getBoolean("manage_system", false);

        // Get predefined rules
        Map<String, Boolean> pre_blocked = new HashMap<>();
        Map<String, Boolean> pre_unused = new HashMap<>();
        Map<String, Boolean> pre_roaming = new HashMap<>();
        try {
            XmlResourceParser xml = context.getResources().getXml(R.xml.predefined);
            int eventType = xml.getEventType();
            while (eventType != XmlPullParser.END_DOCUMENT) {
                if (eventType == XmlPullParser.START_TAG && "rule".equals(xml.getName())) {
                    String pkg = xml.getAttributeValue(null, "package");
                    boolean pblocked = xml.getAttributeBooleanValue(null, "blocked", false);
                    boolean punused = xml.getAttributeBooleanValue(null, "unused", false);
                    boolean proaming = xml.getAttributeBooleanValue(null, "roaming", whitelist_roaming);
                    pre_blocked.put(pkg, pblocked);
                    pre_unused.put(pkg, punused);
                    pre_roaming.put(pkg, proaming);
                    Log.i(tag, "Predefined " + pkg + " blocked=" + pblocked + " unused=" + punused + " roaming=" + proaming);
                }
                eventType = xml.next();
            }
        } catch (Throwable ex) {
            Log.e(tag, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        // Build rule list
        List<Rule> listRules = new ArrayList<>();
        for (PackageInfo info : context.getPackageManager().getInstalledPackages(0)) {
            boolean system = ((info.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
            if (!system || manage_system || all) {
                Rule rule = new Rule(info, context);

                rule.system = system;

                rule.wifi_default = (pre_blocked.containsKey(info.packageName) ? pre_blocked.get(info.packageName) : whitelist_wifi);
                rule.other_default = (pre_blocked.containsKey(info.packageName) ? pre_blocked.get(info.packageName) : whitelist_other);
                rule.unused_default = (pre_unused.containsKey(info.packageName) ? pre_unused.get(info.packageName) : false);
                rule.roaming_default = (pre_roaming.containsKey(info.packageName) ? pre_roaming.get(info.packageName) : whitelist_roaming);

                rule.wifi_blocked = (system && !manage_system ? false : wifi.getBoolean(info.packageName, rule.wifi_default));
                rule.other_blocked = (system && !manage_system ? false : other.getBoolean(info.packageName, rule.other_default));
                rule.unused = unused.getBoolean(info.packageName, rule.unused_default);
                rule.roaming = roaming.getBoolean(info.packageName, rule.roaming_default);

                rule.changed = (rule.wifi_blocked != whitelist_wifi ||
                        rule.other_blocked != whitelist_other ||
                        rule.unused ||
                        (!rule.other_blocked || rule.unused) && rule.roaming && rule.roaming != whitelist_roaming);

                listRules.add(rule);
            }
        }

        // Sort rule list
        Collections.sort(listRules);

        return listRules;
    }

    @Override
    public int compareTo(Rule other) {
        if ((changed || unused) == (other.changed || other.unused)) {
            int i = name.compareToIgnoreCase(other.name);
            return (i == 0 ? info.packageName.compareTo(other.info.packageName) : i);
        }
        return (changed || unused ? -1 : 1);
    }
}
