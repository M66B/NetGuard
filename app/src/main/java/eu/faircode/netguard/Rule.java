package eu.faircode.netguard;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.preference.PreferenceManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Rule implements Comparable<Rule> {
    public PackageInfo info;
    public String name;
    public boolean system;
    public boolean disabled;
    public boolean wifi_blocked;
    public boolean other_blocked;
    public boolean unused;
    public boolean changed;
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
    }

    public static List<Rule> getRules(boolean all, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences wifi = context.getSharedPreferences("wifi", Context.MODE_PRIVATE);
        SharedPreferences other = context.getSharedPreferences("other", Context.MODE_PRIVATE);
        SharedPreferences unused = context.getSharedPreferences("unused", Context.MODE_PRIVATE);

        boolean whitelist_wifi = prefs.getBoolean("whitelist_wifi", true);
        boolean whitelist_other = prefs.getBoolean("whitelist_other", true);
        boolean manage_system = prefs.getBoolean("manage_system", false);

        List<Rule> listRules = new ArrayList<>();
        for (PackageInfo info : context.getPackageManager().getInstalledPackages(0)) {
            boolean system = ((info.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0);
            if (!system || manage_system || all) {
                Rule rule = new Rule(info, context);
                rule.system = system;
                rule.wifi_blocked = (system && !manage_system ? false : wifi.getBoolean(info.packageName, whitelist_wifi));
                rule.other_blocked = (system && !manage_system ? false : other.getBoolean(info.packageName, whitelist_other));
                rule.unused = unused.getBoolean(info.packageName, false);
                rule.changed = (rule.wifi_blocked != whitelist_wifi || rule.other_blocked != whitelist_other);
                listRules.add(rule);
            }
        }

        Collections.sort(listRules);

        return listRules;
    }

    public Drawable getIcon(Context context) {
        return info.applicationInfo.loadIcon(context.getPackageManager());
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
