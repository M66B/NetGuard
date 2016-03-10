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
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.ParcelFileDescriptor;
import android.support.v4.content.LocalBroadcastManager;

public class ProxyService extends IntentService {
    private static final String TAG = "NetGuard.Proxy";
    private static final String INTENT_START = "eu.faircode.netguard.START_PROXY";
    private static final String INTENT_STOP = "eu.faircode.netguard.STOP_PROXY";
    private static final String EXTRA_PFD = "PFD";
    private static final String EXTRA_MTU = "MTU";
    private static final String EXTRA_PKG = "PKG";

    private native void jni_set_proxy(int fd, int mtu);

    public ProxyService() {
        super(TAG);
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        if (INTENT_START.equals(intent.getAction())) {
            if (intent.hasExtra(EXTRA_PFD) && intent.hasExtra(EXTRA_MTU)) {
                ParcelFileDescriptor pfd = (ParcelFileDescriptor) intent.getSerializableExtra(EXTRA_PFD);
                int mtu = intent.getIntExtra(EXTRA_MTU, 0);
                jni_set_proxy(pfd.getFd(), mtu);
                if (intent.hasExtra(EXTRA_PKG)) {
                    SharedPreferences apply = getSharedPreferences("apply", Context.MODE_PRIVATE);
                    apply.edit().putBoolean(intent.getStringExtra(EXTRA_PKG), false).apply();
                    Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
                    LocalBroadcastManager.getInstance(this).sendBroadcast(ruleset);
                }
                SinkholeService.reload("proxy start", this);
            }
        } else if (INTENT_STOP.equals(intent.getAction())) {
            jni_set_proxy(0, 0);
            SinkholeService.reload("proxy stop", this);
        }
    }
}
