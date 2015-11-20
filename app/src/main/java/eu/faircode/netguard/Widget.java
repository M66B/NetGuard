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

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.preference.PreferenceManager;
import android.util.Log;
import android.widget.RemoteViews;

public class Widget extends AppWidgetProvider {
    private static final String TAG = "NetGuard.Widget";

    private static final String INTENT_ON = "eu.faircode.netguard.APPWIDGET_ON";
    private static final String INTENT_OFF = "eu.faircode.netguard.APPWIDGET_OFF";

    @Override
    public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds) {
        update(appWidgetIds, appWidgetManager, context);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        super.onReceive(context, intent);

        Log.i(TAG, "Received " + intent);
        Util.logExtras(intent);

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        if (INTENT_OFF.equals(intent.getAction())) {
            prefs.edit().putBoolean("enabled", false).apply();
            SinkholeService.stop(context);

        } else if (INTENT_ON.equals(intent.getAction())) {
            prefs.edit().putBoolean("enabled", true).apply();
            SinkholeService.start(context);
        }
    }

    private static void update(int[] appWidgetIds, AppWidgetManager appWidgetManager, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean enabled = prefs.getBoolean("enabled", false);

        PendingIntent pi;
        if (VpnService.prepare(context) == null)
            pi = PendingIntent.getBroadcast(context, 0, new Intent(enabled ? INTENT_OFF : INTENT_ON), PendingIntent.FLAG_CANCEL_CURRENT);
        else
            pi = PendingIntent.getActivity(context, 0, new Intent(context, ActivityMain.class), PendingIntent.FLAG_CANCEL_CURRENT);

        for (int id : appWidgetIds) {
            RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.widget);
            views.setOnClickPendingIntent(R.id.ivEnabled, pi);
            views.setImageViewResource(R.id.ivEnabled, enabled ? R.mipmap.ic_launcher : R.drawable.ic_security_white_24dp_60);
            appWidgetManager.updateAppWidget(id, views);
        }
    }

    public static void updateWidgets(Context context) {
        AppWidgetManager appWidgetManager = AppWidgetManager.getInstance(context);
        int appWidgetIds[] = AppWidgetManager.getInstance(context).getAppWidgetIds(new ComponentName(context, Widget.class));
        update(appWidgetIds, appWidgetManager, context);
    }
}
