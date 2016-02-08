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
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class ActivityForward extends Activity {
    private static final String TAG = "NetGuard.Forward";
    private static final String ACTION_START_PORT_FORWARD = "eu.faircode.netguard.START_PORT_FORWARD";
    private static final String ACTION_STOP_PORT_FORWARD = "eu.faircode.netguard.STOP_PORT_FORWARD";

    static {
        System.loadLibrary("netguard");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.forward);

        final int protocol = getIntent().getIntExtra("protocol", 0);
        final int source = getIntent().getIntExtra("source", 0);
        final int target = getIntent().getIntExtra("target", 0);
        final int uid = getIntent().getIntExtra("uid", 0);

        String pname;
        if (protocol == 6)
            pname = getString(R.string.menu_protocol_tcp);
        else if (protocol == 17)
            pname = getString(R.string.menu_protocol_udp);
        else
            pname = Integer.toString(protocol);

        TextView tvForward = (TextView) findViewById(R.id.tvForward);
        if (ACTION_START_PORT_FORWARD.equals(getIntent().getAction()))
            tvForward.setText(getString(R.string.msg_forward_start,
                    pname, source, target,
                    TextUtils.join(", ", Util.getApplicationNames(uid, this))));
        else
            tvForward.setText(getString(R.string.msg_forward_stop, pname, source));

        Button btnOk = (Button) findViewById(R.id.btnOk);
        Button btnCancel = (Button) findViewById(R.id.btnCancel);

        btnOk.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (ACTION_START_PORT_FORWARD.equals(getIntent().getAction())) {
                    // am start -a eu.faircode.netguard.START_PORT_FORWARD \
                    // -n eu.faircode.netguard/eu.faircode.netguard.ActivityForward \
                    // --ei protocol <protocol> \
                    // --ei source <source> \
                    // --ei target <target> \
                    // --ei uid <uid> \
                    // --user 0

                } else if (ACTION_STOP_PORT_FORWARD.equals(getIntent().getAction())) {
                    // am start -a eu.faircode.netguard.STOP_PORT_FORWARD \
                    // -n eu.faircode.netguard/eu.faircode.netguard.ActivityForward \
                    // --ei protocol <protocol> \
                    // --ei source <source> \
                    // --user 0
                }

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
