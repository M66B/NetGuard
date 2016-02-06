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

import android.app.IntentService;
import android.content.Intent;

public class ForwardService extends IntentService {
    private static final String TAG = "NetGuard.Forward";
    private static final String ACTION_START_PORT_FORWARD = "eu.faircode.netguard.START_PORT_FORWARD";
    private static final String ACTION_STOP_PORT_FORWARD = "eu.faircode.netguard.STOP_PORT_FORWARD";

    private native void jni_start_port_forward(int source, int target, int uid);

    private native void jni_stop_port_forward(int source);

    static {
        System.loadLibrary("netguard");
    }

    public ForwardService() {
        super(TAG);
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        if (ACTION_START_PORT_FORWARD.equals(intent.getAction())) {
            // am startservice -a eu.faircode.netguard.START_PORT_FORWARD --ei source <source> --ei target <target> --ei uid <uid>
            int source = intent.getIntExtra("source", 0);
            int target = intent.getIntExtra("target", 0);
            int uid = intent.getIntExtra("uid", 0);
            jni_start_port_forward(source, target, uid);

        } else if (ACTION_STOP_PORT_FORWARD.equals(intent.getAction())) {
            // am startservice -a eu.faircode.netguard.STOP_PORT_FORWARD --ei source <source>
            int source = intent.getIntExtra("source", 0);
            jni_stop_port_forward(source);
        }
    }
}
