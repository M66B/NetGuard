package eu.faircode.netguard

import android.annotation.SuppressLint
import android.content.Intent
import android.os.AsyncTask
import android.os.Bundle
import android.util.Log
import android.util.Xml
import android.view.Menu
import android.view.MenuItem
import android.widget.ListView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.IOException
import java.io.OutputStream
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.*

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
*/   class ActivityDns : AppCompatActivity() {
    private var running = false
    private var adapter: AdapterDns? = null
    override fun onCreate(savedInstanceState: Bundle?) {
        Util.setTheme(this)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.resolving)
        supportActionBar!!.setTitle(R.string.setting_show_resolved)
        supportActionBar!!.setDisplayHomeAsUpEnabled(true)
        val lvDns = findViewById<ListView>(R.id.lvDns)
        adapter = DatabaseHelper.getInstance(this)?.let { AdapterDns(this, it.dns) }
        lvDns.adapter = adapter
        running = true
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        val inflater = menuInflater
        inflater.inflate(R.menu.dns, menu)
        return true
    }

    override fun onPrepareOptionsMenu(menu: Menu): Boolean {
        val pm = packageManager
        menu.findItem(R.id.menu_export).isEnabled = intentExport.resolveActivity(pm) != null
        return super.onPrepareOptionsMenu(menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            R.id.menu_refresh -> {
                refresh()
                return true
            }
            R.id.menu_cleanup -> {
                cleanup()
                return true
            }
            R.id.menu_clear -> {
                Util.areYouSure(this, R.string.menu_clear) { clear() }
                return true
            }
            R.id.menu_export -> {
                export()
                return true
            }
        }
        return false
    }

    private fun refresh() {
        updateAdapter()
    }

    private fun cleanup() {
        object : CoroutineAsyncTask<Any?, Any?, Any?>() {
            @SuppressLint("StaticFieldLeak")
            override fun doInBackground(vararg params: Any?): Any? {
                Log.i(TAG, "Cleanup DNS")
                DatabaseHelper.getInstance(this@ActivityDns)?.cleanupDns()
                return null
            }

            override fun onPostExecute(result: Any?) {
                ServiceSinkhole.reload("DNS cleanup", this@ActivityDns, false)
                updateAdapter()
            }
        }.execute(AsyncTask.THREAD_POOL_EXECUTOR)
    }

    private fun clear() {
        object : CoroutineAsyncTask<Any?, Any?, Any?>() {
             override fun doInBackground(vararg params: Any?): Any? {
                Log.i(TAG, "Clear DNS")
                DatabaseHelper.getInstance(this@ActivityDns)?.clearDns()
                return null
            }

            override fun onPostExecute(result: Any?) {
                ServiceSinkhole.reload("DNS clear", this@ActivityDns, false)
                updateAdapter()
            }
        }.execute(AsyncTask.THREAD_POOL_EXECUTOR)
    }

    private fun export() {
        startActivityForResult(intentExport, REQUEST_EXPORT)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        Log.i(TAG, "onActivityResult request=" + requestCode + " result=" + requestCode + " ok=" + (resultCode == RESULT_OK))
        if (requestCode == REQUEST_EXPORT) {
            if (resultCode == RESULT_OK && data != null) handleExport(data)
        }
    }

    // text/xml
    private val intentExport: Intent
        get() {
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            intent.type = "*/*" // text/xml
            intent.putExtra(Intent.EXTRA_TITLE, "netguard_dns_" + SimpleDateFormat("yyyyMMdd").format(Date().time) + ".xml")
            return intent
        }

    private fun handleExport(data: Intent) {
        object : CoroutineAsyncTask<Any?, Any?, Throwable?>() {
            override fun doInBackground(vararg params: Any?): Throwable? {
                var out: OutputStream? = null
                return try {
                    val target = data.data
                    Log.i(TAG, "Writing URI=$target")
                    out = contentResolver.openOutputStream(target!!)
                    xmlExport(out)
                    null
                } catch (ex: Throwable) {
                    Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                    ex
                } finally {
                    if (out != null) try {
                        out.close()
                    } catch (ex: IOException) {
                        Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                    }
                }
            }

            override fun onPostExecute(ex: Throwable?) {
                if (running) {
                    if (ex == null) Toast.makeText(this@ActivityDns, R.string.msg_completed, Toast.LENGTH_LONG).show() else Toast.makeText(this@ActivityDns, ex.toString(), Toast.LENGTH_LONG).show()
                }
            }
        }.execute(AsyncTask.THREAD_POOL_EXECUTOR)
    }

    @Throws(IOException::class)
    private fun xmlExport(out: OutputStream?) {
        val serializer = Xml.newSerializer()
        serializer.setOutput(out, "UTF-8")
        serializer.startDocument(null, true)
        serializer.setFeature("http://xmlpull.org/v1/doc/features.html#indent-output", true)
        serializer.startTag(null, "netguard")
        val df: DateFormat = SimpleDateFormat("E, d MMM yyyy HH:mm:ss Z", Locale.US) // RFC 822
        DatabaseHelper.getInstance(this)?.dns.use { cursor ->
            val colTime = cursor?.getColumnIndex("time")
            val colQName = cursor?.getColumnIndex("qname")
            val colAName = cursor?.getColumnIndex("aname")
            val colResource = cursor?.getColumnIndex("resource")
            val colTTL = cursor?.getColumnIndex("ttl")
            if (cursor != null) {
                while (cursor.moveToNext()) {
                    val time = colTime?.let { cursor.getLong(it) }
                    val qname = colQName?.let { cursor.getString(it) }
                    val aname = colAName?.let { cursor.getString(it) }
                    val resource = colResource?.let { cursor.getString(it) }
                    val ttl = colTTL?.let { cursor.getInt(it) }
                    serializer.startTag(null, "dns")
                    serializer.attribute(null, "time", df.format(time))
                    serializer.attribute(null, "qname", qname)
                    serializer.attribute(null, "aname", aname)
                    serializer.attribute(null, "resource", resource)
                    serializer.attribute(null, "ttl", ttl?.let { it.toString() })
                    serializer.endTag(null, "dns")
                }
            }
        }
        serializer.endTag(null, "netguard")
        serializer.endDocument()
        serializer.flush()
    }

    private fun updateAdapter() {
        if (adapter != null) adapter!!.changeCursor(DatabaseHelper.getInstance(this)?.dns)
    }

    override fun onDestroy() {
        running = false
        adapter = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "NetGuard.DNS"
        private const val REQUEST_EXPORT = 1
    }
}