package eu.faircode.netguard;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.graphics.drawable.Drawable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class Rule implements Comparable<Rule> {
    public PackageInfo info;
    public String name;
    public boolean wifi_blocked;
    public boolean other_blocked;

    private Rule(PackageInfo info, boolean wifi_blocked, boolean other_blocked, Context context) {
        this.info = info;
        this.name = info.applicationInfo.loadLabel(context.getPackageManager()).toString();
        this.wifi_blocked = wifi_blocked;
        this.other_blocked = other_blocked;
    }

    public static List<Rule> getRules(Context context) {
        SharedPreferences wifi = context.getSharedPreferences("wifi", Context.MODE_PRIVATE);
        SharedPreferences other = context.getSharedPreferences("other", Context.MODE_PRIVATE);

        List<Rule> listRules = new ArrayList<>();
        for (PackageInfo info : context.getPackageManager().getInstalledPackages(0))
            listRules.add(new Rule(
                    info,
                    wifi.getBoolean(info.packageName, true),
                    other.getBoolean(info.packageName, true),
                    context
            ));

        Collections.sort(listRules);

        return listRules;
    }

    public Drawable getIcon(Context context) {
        return info.applicationInfo.loadIcon(context.getPackageManager());
    }

    @Override
    public int compareTo(Rule other) {
        int i = this.name.compareTo(other.name);
        return (i == 0 ? this.info.packageName.compareTo(other.info.packageName) : i);
    }
}
