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

import android.app.Activity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class ActivityForwardApproval extends Activity {
    private static final String TAG = "NetGuard.Forward";
    private static final String ACTION_START_PORT_FORWARD = "eu.faircode.netguard.START_PORT_FORWARD";
    private static final String ACTION_STOP_PORT_FORWARD = "eu.faircode.netguard.STOP_PORT_FORWARD";

    static {
        System.loadLibrary("netguard");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.forwardapproval);

        final int protocol = getIntent().getIntExtra("protocol", 0);
        final int dport = getIntent().getIntExtra("dport", 0);
        String addr = getIntent().getStringExtra("raddr");
        final int rport = getIntent().getIntExtra("rport", 0);
        final int ruid = getIntent().getIntExtra("ruid", 0);
        final String raddr = (addr == null ? "127.0.0.1" : addr);

        String pname;
        if (protocol == 6)
            pname = getString(R.string.menu_protocol_tcp);
        else if (protocol == 17)
            pname = getString(R.string.menu_protocol_udp);
        else
            pname = Integer.toString(protocol);

        TextView tvForward = (TextView) findViewById(R.id.tvForward);
        if (ACTION_START_PORT_FORWARD.equals(getIntent().getAction()))
            tvForward.setText(getString(R.string.msg_start_forward,
                    pname, dport, raddr, rport,
                    TextUtils.join(", ", Util.getApplicationNames(ruid, this))));
        else
            tvForward.setText(getString(R.string.msg_stop_forward, pname, dport));

        Button btnOk = (Button) findViewById(R.id.btnOk);
        Button btnCancel = (Button) findViewById(R.id.btnCancel);

        btnOk.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (ACTION_START_PORT_FORWARD.equals(getIntent().getAction())) {
/*
am start -a eu.faircode.netguard.START_PORT_FORWARD \
-n eu.faircode.netguard/eu.faircode.netguard.ActivityForwardApproval \
--ei protocol 17 \
--ei dport 53 \
--es raddr 8.8.4.4 \
--ei rport 53 \
--ei ruid 1 \
--user 0
*/
                    Log.i(TAG, "Start forwarding protocol " + protocol + " port " + dport + " to " + raddr + ":" + rport + " uid " + ruid);
                    DatabaseHelper dh = new DatabaseHelper(ActivityForwardApproval.this);
                    dh.deleteForward(protocol, dport);
                    dh.addForward(protocol, dport, raddr, rport, ruid);
                    dh.close();

                } else if (ACTION_STOP_PORT_FORWARD.equals(getIntent().getAction())) {
/*
am start -a eu.faircode.netguard.STOP_PORT_FORWARD \
-n eu.faircode.netguard/eu.faircode.netguard.ActivityForwardApproval \
--ei protocol 17 \
--ei dport 53 \
--user 0
*/
                    Log.i(TAG, "Stop forwarding protocol " + protocol + " port " + dport);
                    new DatabaseHelper(ActivityForwardApproval.this)
                            .deleteForward(protocol, dport)
                            .close();
                }

                SinkholeService.reload(null, "forwarding", ActivityForwardApproval.this);

                finish();
            }
        });

        btnCancel.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                finish();
            }
        });
    }
}
