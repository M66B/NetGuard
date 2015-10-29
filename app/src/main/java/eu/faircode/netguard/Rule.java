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

    private Rule(PackageInfo info, boolean wifi_blocked, boolean other_blocked, boolean unused, boolean changed, Context context) {
        PackageManager pm = context.getPackageManager();
        this.info = info;
        this.name = info.applicationInfo.loadLabel(pm).toString();
        this.system = ((info.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0);

        int setting = pm.getApplicationEnabledSetting(info.packageName);
        if (setting == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT)
            this.disabled = !info.applicationInfo.enabled;
        else
            this.disabled = (setting != PackageManager.COMPONENT_ENABLED_STATE_ENABLED);

        this.wifi_blocked = wifi_blocked;
        this.other_blocked = other_blocked;
        this.unused = unused;
        this.changed = changed;
    }

    public static List<Rule> getRules(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences wifi = context.getSharedPreferences("wifi", Context.MODE_PRIVATE);
        SharedPreferences other = context.getSharedPreferences("other", Context.MODE_PRIVATE);
        SharedPreferences punused = context.getSharedPreferences("unused", Context.MODE_PRIVATE);

        boolean wlWifi = prefs.getBoolean("whitelist_wifi", true);
        boolean wlOther = prefs.getBoolean("whitelist_other", true);

        List<Rule> listRules = new ArrayList<>();
        for (PackageInfo info : context.getPackageManager().getInstalledPackages(0)) {
            boolean blWifi = wifi.getBoolean(info.packageName, wlWifi);
            boolean blOther = other.getBoolean(info.packageName, wlOther);
            boolean unused = punused.getBoolean(info.packageName, false);
            boolean changed = (blWifi != wlWifi || blOther != wlOther);
            listRules.add(new Rule(info, blWifi, blOther, unused, changed, context));
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
