package eu.faircode.netguard

import android.app.Activity
import android.os.Bundle
import android.text.TextUtils
import android.util.Log
import android.widget.Button
import android.widget.TextView
import java.net.InetAddress
import kotlin.system.exitProcess

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
*/   class ActivityForwardApproval : Activity() {
    companion object {
        private const val TAG = "NetGuard.Forward"
        private const val ACTION_START_PORT_FORWARD = "eu.faircode.netguard.START_PORT_FORWARD"
        private const val ACTION_STOP_PORT_FORWARD = "eu.faircode.netguard.STOP_PORT_FORWARD"

        init {
            try {
                System.loadLibrary("netguard")
            } catch (ignored: UnsatisfiedLinkError) {
                exitProcess(1)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.forwardapproval)
        val protocol = intent.getIntExtra("protocol", 0)
        val dport = intent.getIntExtra("dport", 0)
        val addr = intent.getStringExtra("raddr")
        val rport = intent.getIntExtra("rport", 0)
        val ruid = intent.getIntExtra("ruid", 0)
        val raddr = addr ?: "127.0.0.1"
        try {
            val iraddr = InetAddress.getByName(raddr)
            require(!(rport < 1024 && (iraddr.isLoopbackAddress || iraddr.isAnyLocalAddress))) { "Port forwarding to privileged port on local address not possible" }
        } catch (ex: Throwable) {
            Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
            finish()
        }
        val pname: String = if (protocol == 6) getString(R.string.menu_protocol_tcp) else if (protocol == 17) getString(R.string.menu_protocol_udp) else protocol.toString()
        val tvForward = findViewById<TextView>(R.id.tvForward)
        if (ACTION_START_PORT_FORWARD == intent.action) tvForward.text = getString(R.string.msg_start_forward,
                pname, dport, raddr, rport,
                TextUtils.join(", ", Util.getApplicationNames(ruid, this))) else tvForward.text = getString(R.string.msg_stop_forward, pname, dport)
        val btnOk = findViewById<Button>(R.id.btnOk)
        val btnCancel = findViewById<Button>(R.id.btnCancel)
        btnOk.setOnClickListener {
            if (ACTION_START_PORT_FORWARD == intent.action) {
        /*
        am start -a eu.faircode.netguard.START_PORT_FORWARD \
        -n eu.faircode.netguard/eu.faircode.netguard.ActivityForwardApproval \
        --ei protocol 17 \
        --ei dport 53 \
        --es raddr 8.8.4.4 \
        --ei rport 53 \
        --ei ruid 9999 \
        --user 0
        */
                Log.i(TAG, "Start forwarding protocol $protocol port $dport to $raddr/$rport uid $ruid")
                val dh = DatabaseHelper.getInstance(this@ActivityForwardApproval)
                dh?.deleteForward(protocol, dport)
                dh?.addForward(protocol, dport, raddr, rport, ruid)
            } else if (ACTION_STOP_PORT_FORWARD == intent.action) {
        /*
        am start -a eu.faircode.netguard.STOP_PORT_FORWARD \
        -n eu.faircode.netguard/eu.faircode.netguard.ActivityForwardApproval \
        --ei protocol 17 \
        --ei dport 53 \
        --user 0
        */
                Log.i(TAG, "Stop forwarding protocol $protocol port $dport")
                DatabaseHelper.getInstance(this@ActivityForwardApproval)?.deleteForward(protocol, dport)
            }
            ServiceSinkhole.reload("forwarding", this@ActivityForwardApproval, false)
            finish()
        }
        btnCancel.setOnClickListener { finish() }
    }
}