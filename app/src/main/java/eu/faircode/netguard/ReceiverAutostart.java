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

    Copyright 2015-2017 by Marcel Bokhorst (M66B)
*/

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.util.Log;

import java.util.Map;

public class ReceiverAutostart extends BroadcastReceiver {
    private static final String TAG = "NetGuard.Receiver";

    @Override
    public void onReceive(final Context context, Intent intent) {
        Log.i(TAG, "Received " + intent);
        Util.logExtras(intent);

        try {
            // Upgrade settings
            upgrade(true, context);

            // Start service
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            if (prefs.getBoolean("enabled", false))
                ServiceSinkhole.start("receiver", context);
            else if (prefs.getBoolean("show_stats", false))
                ServiceSinkhole.run("receiver", context);

            if (Util.isInteractive(context))
                ServiceSinkhole.reloadStats("receiver", context);
        } catch (Throwable ex) {
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

                } else if (oldVersion <= 2017032112)
                    editor.remove("ip6");

            } else {
                Log.i(TAG, "Initializing sdk=" + Build.VERSION.SDK_INT);
                editor.putBoolean("whitelist_wifi", false);
                editor.putBoolean("whitelist_other", false);
                if (Build.VERSION.SDK_INT == Build.VERSION_CODES.LOLLIPOP)
                    editor.putBoolean("filter", true); // Optional
            }

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP)
                editor.putBoolean("filter", true); // Mandatory

            if (!Util.canFilter(context)) {
                editor.putBoolean("log_app", false);
                editor.putBoolean("filter", false);
            }

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