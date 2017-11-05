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

    Copyright 2015-2017 by Marcel Bokhorst (M66B)
*/

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.preference.PreferenceManager;
import android.support.v4.app.NotificationManagerCompat;
import android.util.Log;

import java.util.Map;

public class ReceiverPackageRemoved extends BroadcastReceiver {
    private static final String TAG = "NetGuard.Receiver";

    @Override
    public void onReceive(final Context context, Intent intent) {
        Log.i(TAG, "Received " + intent);
        Util.logExtras(intent);

        int uid = intent.getIntExtra(Intent.EXTRA_UID, 0);
        if (uid > 0) {
            DatabaseHelper dh = DatabaseHelper.getInstance(context);
            dh.clearLog(uid);
            dh.clearAccess(uid, false);

            NotificationManagerCompat.from(context).cancel(uid); // installed notification
            NotificationManagerCompat.from(context).cancel(uid + 10000); // access notification
        }
    }
}