package eu.faircode.netguard

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log
import android.widget.RemoteViews
import androidx.preference.PreferenceManager

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

   Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/   class WidgetMain : AppWidgetProvider() {
    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        update(appWidgetIds, appWidgetManager, context)
    }

    companion object {
        private const val TAG = "NetGuard.Widget"
        private fun update(appWidgetIds: IntArray, appWidgetManager: AppWidgetManager, context: Context) {
            val prefs = PreferenceManager.getDefaultSharedPreferences(context)
            val enabled = prefs.getBoolean("enabled", false)
            try {
                try {
                    val intent = Intent(if (enabled) WidgetAdmin.INTENT_OFF else WidgetAdmin.INTENT_ON)
                    intent.setPackage(context.packageName)
                    val pi = PendingIntent.getBroadcast(context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)
                    for (id in appWidgetIds) {
                        val views = RemoteViews(context.packageName, R.layout.widgetmain)
                        views.setOnClickPendingIntent(R.id.ivEnabled, pi)
                        views.setImageViewResource(R.id.ivEnabled, if (enabled) R.drawable.ic_security_color_24dp else R.drawable.ic_security_white_24dp_60)
                        appWidgetManager.updateAppWidget(id, views)
                    }
                } catch (ex: Throwable) {
                    Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                }
            } catch (ex: Throwable) {
                Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
            }
        }

        @JvmStatic
        fun updateWidgets(context: Context) {
            val appWidgetManager = AppWidgetManager.getInstance(context)
            val appWidgetIds = AppWidgetManager.getInstance(context).getAppWidgetIds(ComponentName(context, WidgetMain::class.java))
            update(appWidgetIds, appWidgetManager, context)
        }
    }
}