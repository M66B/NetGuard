package eu.faircode.netguard

import android.annotation.TargetApi
import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import android.util.Log
import eu.faircode.netguard.ApplicationEx

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
*/   class ApplicationEx : Application() {
    private var mPrevHandler: Thread.UncaughtExceptionHandler? = null
    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Create version=" + Util.getSelfVersionName(this) + "/" + Util.getSelfVersionCode(this))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) createNotificationChannels()
        mPrevHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, ex ->
            if (Util.ownFault(this@ApplicationEx, ex)
                    && Util.isPlayStoreInstall(this@ApplicationEx)) {
                Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                mPrevHandler?.uncaughtException(thread, ex)
            } else {
                Log.w(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                System.exit(1)
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.O)
    private fun createNotificationChannels() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        val foreground = NotificationChannel("foreground", getString(R.string.channel_foreground), NotificationManager.IMPORTANCE_MIN)
        foreground.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
        nm.createNotificationChannel(foreground)
        val notify = NotificationChannel("notify", getString(R.string.channel_notify), NotificationManager.IMPORTANCE_DEFAULT)
        notify.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
        nm.createNotificationChannel(notify)
        val access = NotificationChannel("access", getString(R.string.channel_access), NotificationManager.IMPORTANCE_DEFAULT)
        access.setSound(null, Notification.AUDIO_ATTRIBUTES_DEFAULT)
        nm.createNotificationChannel(access)
    }

    companion object {
        private const val TAG = "NetGuard.App"
    }
}