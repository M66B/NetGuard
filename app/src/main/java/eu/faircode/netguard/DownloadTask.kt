package eu.faircode.netguard

import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.AsyncTask
import android.os.Build
import android.os.PowerManager
import android.os.PowerManager.WakeLock
import android.util.Log
import android.util.TypedValue
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import eu.faircode.netguard.ActivitySettings
import java.io.*
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLConnection

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
*/   class DownloadTask(context: Activity, url: URL, file: File, listener: Listener) : AsyncTask<Any?, Int?, Any?>() {
    private val context: Context
    private val url: URL
    private val file: File
    private val listener: Listener
    private var wakeLock: WakeLock? = null

    interface Listener {
        fun onCompleted()
        fun onCancelled()
        fun onException(ex: Throwable?)
    }

    override fun onPreExecute() {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, javaClass.name)
        wakeLock?.acquire(10*60*1000L /*10 minutes*/)
        showNotification(0)
        Toast.makeText(context, context.getString(R.string.msg_downloading, url.toString()), Toast.LENGTH_SHORT).show()
    }

    protected override fun doInBackground(vararg params: Any?): Any? {
        Log.i(TAG, "Downloading $url into $file")
        var `in`: InputStream? = null
        var out: OutputStream? = null
        var connection: URLConnection? = null
        return try {
            connection = url.openConnection()
            connection.connect()
            if (connection is HttpURLConnection) {
                val httpConnection = connection
                if (httpConnection.responseCode != HttpURLConnection.HTTP_OK) throw IOException(httpConnection.responseCode.toString() + " " + httpConnection.responseMessage)
            }
            val contentLength = connection.contentLength
            Log.i(TAG, "Content length=$contentLength")
            `in` = connection.getInputStream()
            out = FileOutputStream(file)
            var size: Long = 0
            val buffer = ByteArray(4096)
            var bytes: Int? = 0
            while (!isCancelled && `in`.read(buffer).also { bytes = it } != -1) {
                bytes?.let { out.write(buffer, 0, it) }
                size += bytes!!.toLong()
                if (contentLength > 0) publishProgress((size * 100 / contentLength).toInt())
            }
            Log.i(TAG, "Downloaded size=$size")
            null
        } catch (ex: Throwable) {
            ex
        } finally {
            try {
                out?.close()
            } catch (ex: IOException) {
                Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
            }
            try {
                `in`?.close()
            } catch (ex: IOException) {
                Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
            }
            if (connection is HttpURLConnection) connection.disconnect()
        }
    }

    protected override fun onProgressUpdate(vararg values: Int?) {
        super.onProgressUpdate(*values)
        values[0]?.let { showNotification(it) }
    }

    override fun onCancelled() {
        super.onCancelled()
        Log.i(TAG, "Cancelled")
        listener.onCancelled()
    }

    override fun onPostExecute(result: Any?) {
        wakeLock!!.release()
        NotificationManagerCompat.from(context).cancel(ServiceSinkhole.NOTIFY_DOWNLOAD)
        if (result is Throwable) {
            Log.e(TAG, """
     $result
     ${Log.getStackTraceString(result as Throwable?)}
     """.trimIndent())
            listener.onException(result as Throwable?)
        } else listener.onCompleted()
    }

    private fun showNotification(progress: Int) {
        val main = Intent(context, ActivitySettings::class.java)
        val pi = PendingIntent.getActivity(context, ServiceSinkhole.NOTIFY_DOWNLOAD, main, PendingIntent.FLAG_UPDATE_CURRENT)
        val tv = TypedValue()
        context.theme.resolveAttribute(R.attr.colorOff, tv, true)
        val builder = NotificationCompat.Builder(context, "notify")
        builder.setSmallIcon(R.drawable.ic_file_download_white_24dp)
                .setContentTitle(context.getString(R.string.app_name))
                .setContentText(context.getString(R.string.msg_downloading, url.toString()))
                .setContentIntent(pi)
                .setProgress(100, progress, false)
                .setColor(tv.data)
                .setOngoing(true)
                .setAutoCancel(false)
        builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                .setVisibility(NotificationCompat.VISIBILITY_SECRET)
        NotificationManagerCompat.from(context).notify(ServiceSinkhole.NOTIFY_DOWNLOAD, builder.build())
    }

    companion object {
        private const val TAG = "NetGuard.Download"
    }

    init {
        this.context = context
        this.url = url
        this.file = file
        this.listener = listener
    }
}