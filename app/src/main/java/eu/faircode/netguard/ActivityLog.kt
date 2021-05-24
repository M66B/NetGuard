package eu.faircode.netguard

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.SharedPreferences
import android.content.SharedPreferences.OnSharedPreferenceChangeListener
import android.database.Cursor
import android.net.Uri
import android.os.AsyncTask
import android.os.Build
import android.os.Bundle
import android.text.TextUtils
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.*
import android.widget.AdapterView.OnItemClickListener
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.SearchView
import androidx.appcompat.widget.SwitchCompat
import androidx.core.app.NavUtils
import androidx.preference.PreferenceManager
import eu.faircode.netguard.*
import eu.faircode.netguard.DatabaseHelper.LogChangedListener
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.OutputStream
import java.net.InetAddress
import java.net.UnknownHostException
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
*/   class ActivityLog : AppCompatActivity(), OnSharedPreferenceChangeListener {
    private var running = false
    private var lvLog: ListView? = null
    private var adapter: AdapterLog? = null
    private var menuSearch: MenuItem? = null
    private var live = false
    private var resolve = false
    private var organization = false
    private var vpn4: InetAddress? = null
    private var vpn6: InetAddress? = null
    private val listener = object : LogChangedListener {
        override fun onChanged() {
            runOnUiThread { updateAdapter() }
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        if (!IAB.isPurchased(ActivityPro.SKU_LOG, this)) {
            startActivity(Intent(this, ActivityPro::class.java))
            finish()
        }
        Util.setTheme(this)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.logging)
        running = true

        // Action bar
        val actionView = layoutInflater.inflate(R.layout.actionlog, null, false)
        val swEnabled: SwitchCompat = actionView.findViewById(R.id.swEnabled)
        supportActionBar!!.setDisplayShowCustomEnabled(true)
        supportActionBar!!.customView = actionView
        supportActionBar!!.setTitle(R.string.menu_log)
        supportActionBar!!.setDisplayHomeAsUpEnabled(true)

        // Get settings
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        resolve = prefs.getBoolean("resolve", false)
        organization = prefs.getBoolean("organization", false)
        val log = prefs.getBoolean("log", false)

        // Show disabled message
        val tvDisabled = findViewById<TextView>(R.id.tvDisabled)
        tvDisabled.visibility = if (log) View.GONE else View.VISIBLE

        // Set enabled switch
        swEnabled.isChecked = log
        swEnabled.setOnCheckedChangeListener { buttonView, isChecked -> prefs.edit().putBoolean("log", isChecked).apply() }

        // Listen for preference changes
        prefs.registerOnSharedPreferenceChangeListener(this)
        lvLog = findViewById(R.id.lvLog)
        val udp = prefs.getBoolean("proto_udp", true)
        val tcp = prefs.getBoolean("proto_tcp", true)
        val other = prefs.getBoolean("proto_other", true)
        val allowed = prefs.getBoolean("traffic_allowed", true)
        val blocked = prefs.getBoolean("traffic_blocked", true)
        adapter = DatabaseHelper.getInstance(this)?.let { AdapterLog(this, it.getLog(udp, tcp, other, allowed, blocked), resolve, organization) }
        adapter!!.filterQueryProvider = FilterQueryProvider { constraint -> DatabaseHelper.getInstance(this@ActivityLog)?.searchLog(constraint.toString()) }
        lvLog?.adapter = adapter
        try {
            vpn4 = InetAddress.getByName(prefs.getString("vpn4", "10.1.10.1"))
            vpn6 = InetAddress.getByName(prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1"))
        } catch (ex: UnknownHostException) {
            Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
        }
        lvLog?.onItemClickListener = OnItemClickListener { parent, view, position, id ->
            val pm = packageManager
            val cursor = adapter!!.getItem(position) as Cursor
            val time = cursor.getLong(cursor.getColumnIndex("time"))
            val version = cursor.getInt(cursor.getColumnIndex("version"))
            val protocol = cursor.getInt(cursor.getColumnIndex("protocol"))
            val saddr = cursor.getString(cursor.getColumnIndex("saddr"))
            val sport = if (cursor.isNull(cursor.getColumnIndex("sport"))) -1 else cursor.getInt(cursor.getColumnIndex("sport"))
            val daddr = cursor.getString(cursor.getColumnIndex("daddr"))
            val dport = if (cursor.isNull(cursor.getColumnIndex("dport"))) -1 else cursor.getInt(cursor.getColumnIndex("dport"))
            val dname = cursor.getString(cursor.getColumnIndex("dname"))
            val uid = if (cursor.isNull(cursor.getColumnIndex("uid"))) -1 else cursor.getInt(cursor.getColumnIndex("uid"))
            val allowed = if (cursor.isNull(cursor.getColumnIndex("allowed"))) -1 else cursor.getInt(cursor.getColumnIndex("allowed"))

            // Get external address
            var addr: InetAddress? = null
            try {
                addr = InetAddress.getByName(daddr)
            } catch (ex: UnknownHostException) {
                Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
            }
            val ip: String
            val port: Int
            if (addr == vpn4 || addr == vpn6) {
                ip = saddr
                port = sport
            } else {
                ip = daddr
                port = dport
            }

            // Build popup menu
            val popup = PopupMenu(this@ActivityLog, findViewById(R.id.vwPopupAnchor))
            popup.inflate(R.menu.log)

            // Application name
            if (uid >= 0) popup.menu.findItem(R.id.menu_application).title = TextUtils.join(", ", Util.getApplicationNames(uid, this@ActivityLog)) else popup.menu.removeItem(R.id.menu_application)

            // Destination IP
            popup.menu.findItem(R.id.menu_protocol).title = Util.getProtocolName(protocol, version, false)

            // Whois
            val lookupIP = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.dnslytics.com/whois-lookup/$ip"))
            if (pm.resolveActivity(lookupIP, 0) == null) popup.menu.removeItem(R.id.menu_whois) else popup.menu.findItem(R.id.menu_whois).title = getString(R.string.title_log_whois, ip)

            // Lookup port
            val lookupPort = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.speedguide.net/port.php?port=$port"))
            if (port <= 0 || pm.resolveActivity(lookupPort, 0) == null) popup.menu.removeItem(R.id.menu_port) else popup.menu.findItem(R.id.menu_port).title = getString(R.string.title_log_port, port)
            if (prefs.getBoolean("filter", false)) {
                if (uid <= 0) {
                    popup.menu.removeItem(R.id.menu_allow)
                    popup.menu.removeItem(R.id.menu_block)
                }
            } else {
                popup.menu.removeItem(R.id.menu_allow)
                popup.menu.removeItem(R.id.menu_block)
            }
            val packet = Packet()
            packet.version = version
            packet.protocol = protocol
            packet.daddr = daddr
            packet.dport = dport
            packet.time = time
            packet.uid = uid
            packet.allowed = allowed > 0

            // Time
            popup.menu.findItem(R.id.menu_time).title = SimpleDateFormat.getDateTimeInstance().format(time)

            // Handle click
            popup.setOnMenuItemClickListener { menuItem ->
                when (menuItem.itemId) {
                    R.id.menu_application -> {
                        val main = Intent(this@ActivityLog, ActivityMain::class.java)
                        main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid))
                        startActivity(main)
                        true
                    }
                    R.id.menu_whois -> {
                        startActivity(lookupIP)
                        true
                    }
                    R.id.menu_port -> {
                        startActivity(lookupPort)
                        true
                    }
                    R.id.menu_allow -> {
                        if (IAB.isPurchased(ActivityPro.SKU_FILTER, this@ActivityLog)) {
                            DatabaseHelper.getInstance(this@ActivityLog)?.updateAccess(packet, dname, 0)
                            ServiceSinkhole.reload("allow host", this@ActivityLog, false)
                            val main = Intent(this@ActivityLog, ActivityMain::class.java)
                            main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid))
                            startActivity(main)
                        } else startActivity(Intent(this@ActivityLog, ActivityPro::class.java))
                        true
                    }
                    R.id.menu_block -> {
                        if (IAB.isPurchased(ActivityPro.SKU_FILTER, this@ActivityLog)) {
                            DatabaseHelper.getInstance(this@ActivityLog)?.updateAccess(packet, dname, 1)
                            ServiceSinkhole.reload("block host", this@ActivityLog, false)
                            val main = Intent(this@ActivityLog, ActivityMain::class.java)
                            main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid))
                            startActivity(main)
                        } else startActivity(Intent(this@ActivityLog, ActivityPro::class.java))
                        true
                    }
                    R.id.menu_copy -> {
                        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = ClipData.newPlainText("netguard", dname ?: daddr)
                        clipboard.setPrimaryClip(clip)
                        true
                    }
                    else -> false
                }
            }

            // Show
            popup.show()
        }
        live = true
    }

    override fun onResume() {
        super.onResume()
        if (live) {
            DatabaseHelper.getInstance(this)?.addLogChangedListener(listener)
            updateAdapter()
        }
    }

    override fun onPause() {
        super.onPause()
        if (live) DatabaseHelper.getInstance(this)?.removeLogChangedListener(listener)
    }

    override fun onDestroy() {
        running = false
        adapter = null
        PreferenceManager.getDefaultSharedPreferences(this).unregisterOnSharedPreferenceChangeListener(this)
        super.onDestroy()
    }

    override fun onSharedPreferenceChanged(prefs: SharedPreferences, name: String) {
        Log.i(TAG, "Preference " + name + "=" + prefs.all[name])
        if ("log" == name) {
            // Get enabled
            val log = prefs.getBoolean(name, false)

            // Display disabled warning
            val tvDisabled = findViewById<TextView>(R.id.tvDisabled)
            tvDisabled.visibility = if (log) View.GONE else View.VISIBLE

            // Check switch state
            val swEnabled: SwitchCompat = supportActionBar!!.customView.findViewById(R.id.swEnabled)
            if (swEnabled.isChecked != log) swEnabled.isChecked = log
            ServiceSinkhole.reload("changed $name", this@ActivityLog, false)
        }
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        val inflater = menuInflater
        inflater.inflate(R.menu.logging, menu)
        menuSearch = menu.findItem(R.id.menu_search)
        val searchView = menuSearch?.actionView as SearchView
        searchView.setOnQueryTextListener(object : SearchView.OnQueryTextListener {
            override fun onQueryTextSubmit(query: String): Boolean {
                if (adapter != null) adapter!!.filter.filter(getUidForName(query))
                return true
            }

            override fun onQueryTextChange(newText: String): Boolean {
                if (adapter != null) adapter!!.filter.filter(getUidForName(newText))
                return true
            }
        })
        searchView.setOnCloseListener {
            if (adapter != null) adapter!!.filter.filter(null)
            true
        }
        return true
    }

    override fun onPrepareOptionsMenu(menu: Menu): Boolean {
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)

        // https://gist.github.com/granoeste/5574148
        val pcap_file = File(getDir("data", MODE_PRIVATE), "netguard.pcap")
        val export = packageManager.resolveActivity(intentPCAPDocument, 0) != null
        menu.findItem(R.id.menu_protocol_udp).isChecked = prefs.getBoolean("proto_udp", true)
        menu.findItem(R.id.menu_protocol_tcp).isChecked = prefs.getBoolean("proto_tcp", true)
        menu.findItem(R.id.menu_protocol_other).isChecked = prefs.getBoolean("proto_other", true)
        menu.findItem(R.id.menu_traffic_allowed).isEnabled = prefs.getBoolean("filter", false)
        menu.findItem(R.id.menu_traffic_allowed).isChecked = prefs.getBoolean("traffic_allowed", true)
        menu.findItem(R.id.menu_traffic_blocked).isChecked = prefs.getBoolean("traffic_blocked", true)
        menu.findItem(R.id.menu_refresh).isEnabled = !menu.findItem(R.id.menu_log_live).isChecked
        menu.findItem(R.id.menu_log_resolve).isChecked = prefs.getBoolean("resolve", false)
        menu.findItem(R.id.menu_log_organization).isChecked = prefs.getBoolean("organization", false)
        menu.findItem(R.id.menu_pcap_enabled).isChecked = prefs.getBoolean("pcap", false)
        menu.findItem(R.id.menu_pcap_export).isEnabled = pcap_file.exists() && export
        return super.onPrepareOptionsMenu(menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
        val pcap_file = File(getDir("data", MODE_PRIVATE), "netguard.pcap")
        return when (item.itemId) {
            android.R.id.home -> {
                Log.i(TAG, "Up")
                NavUtils.navigateUpFromSameTask(this)
                true
            }
            R.id.menu_protocol_udp -> {
                item.isChecked = !item.isChecked
                prefs.edit().putBoolean("proto_udp", item.isChecked).apply()
                updateAdapter()
                true
            }
            R.id.menu_protocol_tcp -> {
                item.isChecked = !item.isChecked
                prefs.edit().putBoolean("proto_tcp", item.isChecked).apply()
                updateAdapter()
                true
            }
            R.id.menu_protocol_other -> {
                item.isChecked = !item.isChecked
                prefs.edit().putBoolean("proto_other", item.isChecked).apply()
                updateAdapter()
                true
            }
            R.id.menu_traffic_allowed -> {
                item.isChecked = !item.isChecked
                prefs.edit().putBoolean("traffic_allowed", item.isChecked).apply()
                updateAdapter()
                true
            }
            R.id.menu_traffic_blocked -> {
                item.isChecked = !item.isChecked
                prefs.edit().putBoolean("traffic_blocked", item.isChecked).apply()
                updateAdapter()
                true
            }
            R.id.menu_log_live -> {
                item.isChecked = !item.isChecked
                live = item.isChecked
                if (live) {
                    DatabaseHelper.getInstance(this)?.addLogChangedListener(listener)
                    updateAdapter()
                } else DatabaseHelper.getInstance(this)?.removeLogChangedListener(listener)
                true
            }
            R.id.menu_refresh -> {
                updateAdapter()
                true
            }
            R.id.menu_log_resolve -> {
                item.isChecked = !item.isChecked
                prefs.edit().putBoolean("resolve", item.isChecked).apply()
                adapter!!.setResolve(item.isChecked)
                adapter!!.notifyDataSetChanged()
                true
            }
            R.id.menu_log_organization -> {
                item.isChecked = !item.isChecked
                prefs.edit().putBoolean("organization", item.isChecked).apply()
                adapter!!.setOrganization(item.isChecked)
                adapter!!.notifyDataSetChanged()
                true
            }
            R.id.menu_pcap_enabled -> {
                item.isChecked = !item.isChecked
                prefs.edit().putBoolean("pcap", item.isChecked).apply()
                ServiceSinkhole.setPcap(item.isChecked, this@ActivityLog)
                true
            }
            R.id.menu_pcap_export -> {
                startActivityForResult(intentPCAPDocument, REQUEST_PCAP)
                true
            }
            R.id.menu_log_clear -> {
                object : CoroutineAsyncTask<Any?, Any?, Any?>() {
                    override fun doInBackground(vararg params: Any?): Any? {
                        DatabaseHelper.getInstance(this@ActivityLog)?.clearLog(-1)
                        if (prefs.getBoolean("pcap", false)) {
                            ServiceSinkhole.setPcap(false, this@ActivityLog)
                            if (pcap_file.exists() && !pcap_file.delete()) Log.w(TAG, "Delete PCAP failed")
                            ServiceSinkhole.setPcap(true, this@ActivityLog)
                        } else {
                            if (pcap_file.exists() && !pcap_file.delete()) Log.w(TAG, "Delete PCAP failed")
                        }
                        return null
                    }

                    override fun onPostExecute(result: Any?) {
                        if (running) updateAdapter()
                    }
                }.execute(AsyncTask.THREAD_POOL_EXECUTOR)
                true
            }
            R.id.menu_log_support -> {
                val intent = Intent(Intent.ACTION_VIEW)
                intent.data = Uri.parse("https://github.com/M66B/NetGuard/blob/master/FAQ.md#user-content-faq27")
                if (packageManager.resolveActivity(intent, 0) != null) startActivity(intent)
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun updateAdapter() {
        if (adapter != null) {
            val prefs = PreferenceManager.getDefaultSharedPreferences(this)
            val udp = prefs.getBoolean("proto_udp", true)
            val tcp = prefs.getBoolean("proto_tcp", true)
            val other = prefs.getBoolean("proto_other", true)
            val allowed = prefs.getBoolean("traffic_allowed", true)
            val blocked = prefs.getBoolean("traffic_blocked", true)
            adapter!!.changeCursor(DatabaseHelper.getInstance(this)?.getLog(udp, tcp, other, allowed, blocked))
            if (menuSearch != null && menuSearch!!.isActionViewExpanded) {
                val searchView = menuSearch!!.actionView as SearchView
                adapter!!.filter.filter(getUidForName(searchView.query.toString()))
            }
        }
    }

    private fun getUidForName(query: String?): String? {
        if (query != null && query.length > 0) {
            for (rule in Rule.getRules(true, this@ActivityLog)) if (rule.name != null && rule.name.toLowerCase().contains(query.toLowerCase())) {
                val newQuery = Integer.toString(rule.uid)
                Log.i(TAG, "Search " + query + " found " + rule.name + " new " + newQuery)
                return newQuery
            }
            Log.i(TAG, "Search $query not found")
        }
        return query
    }

    private val intentPCAPDocument: Intent
        get() {
            val intent: Intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            intent.type = "application/octet-stream"
            intent.putExtra(Intent.EXTRA_TITLE, "netguard_" + SimpleDateFormat("yyyyMMdd").format(Date().time) + ".pcap")
            return intent
        }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        Log.i(TAG, "onActivityResult request=" + requestCode + " result=" + requestCode + " ok=" + (resultCode == RESULT_OK))
        if (requestCode == REQUEST_PCAP) {
            if (resultCode == RESULT_OK && data != null) handleExportPCAP(data)
        } else {
            Log.w(TAG, "Unknown activity result request=$requestCode")
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    private fun handleExportPCAP(data: Intent) {
        object : CoroutineAsyncTask<Any?, Any?, Throwable?>() {
            override fun doInBackground(vararg params: Any?): Throwable? {
                var out: OutputStream? = null
                var `in`: FileInputStream? = null
                return try {
                    // Stop capture
                    ServiceSinkhole.setPcap(false, this@ActivityLog)
                    var target = data.data
                    if (data.hasExtra("org.openintents.extra.DIR_PATH")) target = Uri.parse(target.toString() + "/netguard.pcap")
                    Log.i(TAG, "Export PCAP URI=$target")
                    out = contentResolver.openOutputStream(target!!)
                    val pcap = File(getDir("data", MODE_PRIVATE), "netguard.pcap")
                    `in` = FileInputStream(pcap)
                    var len: Int
                    var total: Long = 0
                    val buf = ByteArray(4096)
                    while (`in`.read(buf).also { len = it } > 0) {
                        out!!.write(buf, 0, len)
                        total += len.toLong()
                    }
                    Log.i(TAG, "Copied bytes=$total")
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
                    if (`in` != null) try {
                        `in`.close()
                    } catch (ex: IOException) {
                        Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                    }

                    // Resume capture
                    val prefs = PreferenceManager.getDefaultSharedPreferences(this@ActivityLog)
                    if (prefs.getBoolean("pcap", false)) ServiceSinkhole.setPcap(true, this@ActivityLog)
                }
            }

            override fun onPostExecute(ex: Throwable?) {
                if (ex == null) Toast.makeText(this@ActivityLog, R.string.msg_completed, Toast.LENGTH_LONG).show() else Toast.makeText(this@ActivityLog, ex.toString(), Toast.LENGTH_LONG).show()
            }
        }.execute(AsyncTask.THREAD_POOL_EXECUTOR)
    }

    companion object {
        private const val TAG = "NetGuard.Log"
        private const val REQUEST_PCAP = 1
    }
}