package eu.faircode.netguard

import android.annotation.SuppressLint
import android.database.Cursor
import android.os.AsyncTask
import android.os.Bundle
import android.view.*
import android.widget.*
import android.widget.AdapterView.OnItemClickListener
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import eu.faircode.netguard.DatabaseHelper.ForwardChangedListener
import java.net.InetAddress

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
*/   class ActivityForwarding : AppCompatActivity() {
    private var running = false
    private var lvForwarding: ListView? = null
    private var adapter: AdapterForwarding? = null
    private var dialog: AlertDialog? = null
    private val listener = object : ForwardChangedListener {
        override fun onChanged() {
            runOnUiThread { if (adapter != null) adapter!!.changeCursor(DatabaseHelper.getInstance(this@ActivityForwarding)?.forwarding) }
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        Util.setTheme(this)
        super.onCreate(savedInstanceState)
        setContentView(R.layout.forwarding)
        running = true
        supportActionBar!!.setTitle(R.string.setting_forwarding)
        supportActionBar!!.setDisplayHomeAsUpEnabled(true)
        lvForwarding = findViewById(R.id.lvForwarding)

        adapter = DatabaseHelper.getInstance(this)?.let { AdapterForwarding(this, it.forwarding) }
        lvForwarding?.adapter = adapter
        lvForwarding?.onItemClickListener = OnItemClickListener { parent, view, position, id ->
            val cursor = adapter!!.getItem(position) as Cursor
            val protocol = cursor.getInt(cursor.getColumnIndex("protocol"))
            val dport = cursor.getInt(cursor.getColumnIndex("dport"))
            val raddr = cursor.getString(cursor.getColumnIndex("raddr"))
            val rport = cursor.getInt(cursor.getColumnIndex("rport"))
            val popup = PopupMenu(this@ActivityForwarding, view)
            popup.inflate(R.menu.forward)
            popup.menu.findItem(R.id.menu_port).title = Util.getProtocolName(protocol, 0, false) + " " +
                    dport + " > " + raddr + "/" + rport
            popup.setOnMenuItemClickListener { menuItem ->
                if (menuItem.itemId == R.id.menu_delete) {
                    DatabaseHelper.getInstance(this@ActivityForwarding)?.deleteForward(protocol, dport)
                    ServiceSinkhole.reload("forwarding", this@ActivityForwarding, false)
                    adapter = DatabaseHelper.getInstance(this@ActivityForwarding)?.let {
                        AdapterForwarding(this@ActivityForwarding,
                                it.forwarding)
                    }
                    lvForwarding?.adapter = adapter
                }
                false
            }
            popup.show()
        }
    }

    override fun onResume() {
        super.onResume()
        DatabaseHelper.getInstance(this)?.addForwardChangedListener(listener)
        if (adapter != null) adapter!!.changeCursor(DatabaseHelper.getInstance(this@ActivityForwarding)?.forwarding)
    }

    override fun onPause() {
        super.onPause()
        DatabaseHelper.getInstance(this)?.removeForwardChangedListener(listener)
    }

    override fun onDestroy() {
        running = false
        adapter = null
        if (dialog != null) {
            dialog!!.dismiss()
            dialog = null
        }
        super.onDestroy()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        val inflater = menuInflater
        inflater.inflate(R.menu.forwarding, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.menu_add -> {
                val inflater = LayoutInflater.from(this)
                val view = inflater.inflate(R.layout.forwardadd, null, false)
                val spProtocol = view.findViewById<Spinner>(R.id.spProtocol)
                val etDPort = view.findViewById<EditText>(R.id.etDPort)
                val etRAddr = view.findViewById<EditText>(R.id.etRAddr)
                val etRPort = view.findViewById<EditText>(R.id.etRPort)
                val pbRuid = view.findViewById<ProgressBar>(R.id.pbRUid)
                val spRuid = view.findViewById<Spinner>(R.id.spRUid)
                val task: AsyncTask<*, *, *> = object : AsyncTask<Any?, Any?, List<Rule?>>() {
                    override fun onPreExecute() {
                        pbRuid.visibility = View.VISIBLE
                        spRuid.visibility = View.GONE
                    }

                    protected override fun doInBackground(vararg params: Any?): List<Rule?>? {
                        return Rule.getRules(true, this@ActivityForwarding)
                    }

                    override fun onPostExecute(rules: List<Rule?>) {
                        val spinnerArrayAdapter: ArrayAdapter<*> = ArrayAdapter<Any?>(this@ActivityForwarding,
                                android.R.layout.simple_spinner_item, rules)
                        spRuid.adapter = spinnerArrayAdapter
                        pbRuid.visibility = View.GONE
                        spRuid.visibility = View.VISIBLE
                    }
                }
                task.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR)
                dialog = AlertDialog.Builder(this)
                        .setView(view)
                        .setCancelable(true)
                        .setPositiveButton(android.R.string.yes) { dialog, which ->
                            try {
                                val pos = spProtocol.selectedItemPosition
                                val values = resources.getStringArray(R.array.protocolValues)
                                val protocol = Integer.valueOf(values[pos])
                                val dport = etDPort.text.toString().toInt()
                                val raddr = etRAddr.text.toString()
                                val rport = etRPort.text.toString().toInt()
                                val ruid = (spRuid.selectedItem as Rule).uid
                                val iraddr = InetAddress.getByName(raddr)
                                require(!(rport < 1024 && (iraddr.isLoopbackAddress || iraddr.isAnyLocalAddress))) { "Port forwarding to privileged port on local address not possible" }
                                object : CoroutineAsyncTask<Any?, Any?, Throwable?>() {
                                    override fun doInBackground(vararg params: Any?): Throwable? {
                                        return try {
                                            DatabaseHelper.getInstance(this@ActivityForwarding)
                                                    ?.addForward(protocol, dport, raddr, rport, ruid)
                                            null
                                        } catch (ex: Throwable) {
                                            ex
                                        }
                                    }

                                    override fun onPostExecute(ex: Throwable?) {
                                        if (running) if (ex == null) {
                                            ServiceSinkhole.reload("forwarding", this@ActivityForwarding, false)
                                            adapter = DatabaseHelper.getInstance(this@ActivityForwarding)?.let {
                                                AdapterForwarding(this@ActivityForwarding,
                                                        it.forwarding)
                                            }
                                            lvForwarding!!.adapter = adapter
                                        } else Toast.makeText(this@ActivityForwarding, ex.toString(), Toast.LENGTH_LONG).show()
                                    }
                                }.execute(AsyncTask.THREAD_POOL_EXECUTOR)
                            } catch (ex: Throwable) {
                                Toast.makeText(this@ActivityForwarding, ex.toString(), Toast.LENGTH_LONG).show()
                            }
                        }
                        .setNegativeButton(android.R.string.no) { dialog, which ->
                            task.cancel(false)
                            dialog.dismiss()
                        }
                        .setOnDismissListener { dialog = null }
                        .create()
                dialog!!.show()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
}