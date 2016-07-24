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

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Vibrator;
import android.preference.PreferenceManager;
import android.util.Log;

import java.util.Date;

public class WidgetAdmin extends Receiver {
    private static final String TAG = "NetGuard.Widget";

    public static final String INTENT_ON = "eu.faircode.netguard.APPWIDGET_ON";
    public static final String INTENT_OFF = "eu.faircode.netguard.APPWIDGET_OFF";

    @Override
    public void onReceive(Context context, Intent intent) {
        super.onReceive(context, intent);

        Log.i(TAG, "Received " + intent);
        Util.logExtras(intent);

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        // Cancel set alarm
        AlarmManager am = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        PendingIntent pi = PendingIntent.getBroadcast(context, 0, new Intent(INTENT_ON), PendingIntent.FLAG_UPDATE_CURRENT);
        am.cancel(pi);

        // Vibrate
        if (INTENT_OFF.equals(intent.getAction()) || INTENT_ON.equals(intent.getAction())) {
            Vibrator vs = (Vibrator) context.getSystemService(Context.VIBRATOR_SERVICE);
            if (vs.hasVibrator())
                vs.vibrate(50);
        }

        if (INTENT_OFF.equals(intent.getAction())) {
            prefs.edit().putBoolean("enabled", false).apply();
            ServiceSinkhole.stop("widget", context);

            // Auto enable
            int auto = Integer.parseInt(prefs.getString("auto_enable", "0"));
            if (auto > 0) {
                Log.i(TAG, "Scheduling enabled after minutes=" + auto);
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
                    am.set(AlarmManager.RTC_WAKEUP, new Date().getTime() + auto * 60 * 1000L, pi);
                else
                    am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, new Date().getTime() + auto * 60 * 1000L, pi);
            }

        } else if (INTENT_ON.equals(intent.getAction()))
            try {
                prefs.edit().putBoolean("enabled", true).apply();
                ServiceSinkhole.start("widget", context);
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
    }
}
