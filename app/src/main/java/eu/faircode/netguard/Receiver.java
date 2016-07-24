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

import android.app.Notification;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.preference.PreferenceManager;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.NotificationManagerCompat;
import android.text.TextUtils;
import android.util.Log;
import android.util.TypedValue;

import java.util.Map;

public class Receiver extends BroadcastReceiver {
    private static final String TAG = "NetGuard.Receiver";

    @Override
    public void onReceive(final Context context, Intent intent) {
        Log.i(TAG, "Received " + intent);
        Util.logExtras(intent);

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        if (Intent.ACTION_PACKAGE_ADDED.equals(intent.getAction())) {
            // Application added
            if (!intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
                // Show notification
                if (IAB.isPurchased(ActivityPro.SKU_NOTIFY, context) && prefs.getBoolean("install", true)) {
                    int uid = intent.getIntExtra(Intent.EXTRA_UID, -1);
                    notifyNewApplication(uid, context);
                }
            }

        } else if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())) {
            // Application removed
            Rule.clearCache(context);

            if (intent.getBooleanExtra(Intent.EXTRA_DATA_REMOVED, false)) {
                // Remove settings
                String packageName = intent.getData().getSchemeSpecificPart();
                Log.i(TAG, "Deleting settings package=" + packageName);
                context.getSharedPreferences("wifi", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                context.getSharedPreferences("other", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                context.getSharedPreferences("apply", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                context.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                context.getSharedPreferences("screen_other", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                context.getSharedPreferences("roaming", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                context.getSharedPreferences("notify", Context.MODE_PRIVATE).edit().remove(packageName).apply();

                int uid = intent.getIntExtra(Intent.EXTRA_UID, 0);
                if (uid > 0) {
                    DatabaseHelper.getInstance(context).clearAccess(uid, false);

                    NotificationManagerCompat.from(context).cancel(uid); // installed notification
                    NotificationManagerCompat.from(context).cancel(uid + 10000); // access notification
                }
            }

        } else {
            // Upgrade settings
            upgrade(true, context);

            // Start service
            try {
                if (prefs.getBoolean("enabled", false))
                    ServiceSinkhole.start("receiver", context);
                else if (prefs.getBoolean("show_stats", false))
                    ServiceSinkhole.run("receiver", context);
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

            if (Util.isInteractive(context))
                ServiceSinkhole.reloadStats("receiver", context);
        }
    }

    public static void notifyNewApplication(int uid, Context context) {
        if (uid < 0)
            return;

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        try {
            // Get application info
            String name = TextUtils.join(", ", Util.getApplicationNames(uid, context));

            // Get application info
            PackageManager pm = context.getPackageManager();
            String[] packages = pm.getPackagesForUid(uid);
            if (packages == null || packages.length < 1)
                throw new PackageManager.NameNotFoundException(Integer.toString(uid));
            boolean internet = Util.hasInternet(uid, context);

            // Build notification
            Intent main = new Intent(context, ActivityMain.class);
            main.putExtra(ActivityMain.EXTRA_REFRESH, true);
            main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
            PendingIntent pi = PendingIntent.getActivity(context, uid, main, PendingIntent.FLAG_UPDATE_CURRENT);

            Util.setTheme(context);
            TypedValue tv = new TypedValue();
            context.getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
            NotificationCompat.Builder builder = new NotificationCompat.Builder(context)
                    .setSmallIcon(R.drawable.ic_security_white_24dp)
                    .setContentIntent(pi)
                    .setColor(tv.data)
                    .setAutoCancel(true);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
                builder.setContentTitle(name)
                        .setContentText(context.getString(R.string.msg_installed_n));
            else
                builder.setContentTitle(context.getString(R.string.app_name))
                        .setContentText(context.getString(R.string.msg_installed, name));

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                builder.setCategory(Notification.CATEGORY_STATUS)
                        .setVisibility(Notification.VISIBILITY_SECRET);
            }

            // Get defaults
            SharedPreferences prefs_wifi = context.getSharedPreferences("wifi", Context.MODE_PRIVATE);
            SharedPreferences prefs_other = context.getSharedPreferences("other", Context.MODE_PRIVATE);
            boolean wifi = prefs_wifi.getBoolean(packages[0], prefs.getBoolean("whitelist_wifi", true));
            boolean other = prefs_other.getBoolean(packages[0], prefs.getBoolean("whitelist_other", true));

            // Build Wi-Fi action
            Intent riWifi = new Intent(context, ServiceSinkhole.class);
            riWifi.putExtra(ServiceSinkhole.EXTRA_COMMAND, ServiceSinkhole.Command.set);
            riWifi.putExtra(ServiceSinkhole.EXTRA_NETWORK, "wifi");
            riWifi.putExtra(ServiceSinkhole.EXTRA_UID, uid);
            riWifi.putExtra(ServiceSinkhole.EXTRA_PACKAGE, packages[0]);
            riWifi.putExtra(ServiceSinkhole.EXTRA_BLOCKED, !wifi);

            PendingIntent piWifi = PendingIntent.getService(context, uid, riWifi, PendingIntent.FLAG_UPDATE_CURRENT);
            builder.addAction(
                    wifi ? R.drawable.wifi_on : R.drawable.wifi_off,
                    context.getString(wifi ? R.string.title_allow : R.string.title_block),
                    piWifi
            );

            // Build mobile action
            Intent riOther = new Intent(context, ServiceSinkhole.class);
            riOther.putExtra(ServiceSinkhole.EXTRA_COMMAND, ServiceSinkhole.Command.set);
            riOther.putExtra(ServiceSinkhole.EXTRA_NETWORK, "other");
            riOther.putExtra(ServiceSinkhole.EXTRA_UID, uid);
            riOther.putExtra(ServiceSinkhole.EXTRA_PACKAGE, packages[0]);
            riOther.putExtra(ServiceSinkhole.EXTRA_BLOCKED, !other);
            PendingIntent piOther = PendingIntent.getService(context, uid + 10000, riOther, PendingIntent.FLAG_UPDATE_CURRENT);
            builder.addAction(
                    other ? R.drawable.other_on : R.drawable.other_off,
                    context.getString(other ? R.string.title_allow : R.string.title_block),
                    piOther
            );

            // Show notification
            if (internet)
                NotificationManagerCompat.from(context).notify(uid, builder.build());
            else {
                NotificationCompat.BigTextStyle expanded = new NotificationCompat.BigTextStyle(builder);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
                    expanded.bigText(context.getString(R.string.msg_installed_n));
                else
                    expanded.bigText(context.getString(R.string.msg_installed, name));
                expanded.setSummaryText(context.getString(R.string.title_internet));
                NotificationManagerCompat.from(context).notify(uid, expanded.build());
            }

        } catch (PackageManager.NameNotFoundException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
    }

    public static void upgrade(boolean initialized, Context context) {
        synchronized (context.getApplicationContext()) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            int oldVersion = prefs.getInt("version", -1);
            int newVersion = Util.getSelfVersionCode(context);
            if (oldVersion == newVersion)
                return;
            Log.i(TAG, "Upgrading from version " + oldVersion + " to " + newVersion);

            SharedPreferences.Editor editor = prefs.edit();

            if (initialized) {
                if (oldVersion < 38) {
                    Log.i(TAG, "Converting screen wifi/mobile");
                    editor.putBoolean("screen_wifi", prefs.getBoolean("unused", false));
                    editor.putBoolean("screen_other", prefs.getBoolean("unused", false));
                    editor.remove("unused");

                    SharedPreferences unused = context.getSharedPreferences("unused", Context.MODE_PRIVATE);
                    SharedPreferences screen_wifi = context.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE);
                    SharedPreferences screen_other = context.getSharedPreferences("screen_other", Context.MODE_PRIVATE);

                    Map<String, ?> punused = unused.getAll();
                    SharedPreferences.Editor edit_screen_wifi = screen_wifi.edit();
                    SharedPreferences.Editor edit_screen_other = screen_other.edit();
                    for (String key : punused.keySet()) {
                        edit_screen_wifi.putBoolean(key, (Boolean) punused.get(key));
                        edit_screen_other.putBoolean(key, (Boolean) punused.get(key));
                    }
                    edit_screen_wifi.apply();
                    edit_screen_other.apply();
                }
            } else {
                Log.i(TAG, "Initializing sdk=" + Build.VERSION.SDK_INT);
                editor.putBoolean("whitelist_wifi", false);
                editor.putBoolean("whitelist_other", false);
                if (Build.VERSION.SDK_INT == Build.VERSION_CODES.LOLLIPOP)
                    editor.putBoolean("filter", true); // Optional
            }

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP)
                editor.putBoolean("filter", true); // Mandatory

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                editor.remove("show_top");
                if ("data".equals(prefs.getString("sort", "name")))
                    editor.remove("sort");
            }

            if (Util.isPlayStoreInstall(context)) {
                editor.remove("update_check");
                editor.remove("use_hosts");
                editor.remove("hosts_url");
            }

            if (!Util.isDebuggable(context))
                editor.remove("loglevel");

            editor.putInt("version", newVersion);
            editor.apply();
        }
    }
}