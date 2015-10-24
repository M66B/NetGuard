package eu.faircode.netguard;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.preference.PreferenceManager;
import android.util.Log;

public class BootReceiver extends BroadcastReceiver {
    private static final String TAG = "NetGuard.Boot";

    @Override
    public void onReceive(final Context context, Intent intent) {
        Log.i(TAG, "Received " + intent);

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        if (prefs.getBoolean("enabled", false))
            if (VpnService.prepare(context) == null) {
                Intent service = new Intent(context, BlackHoleService.class);
                service.putExtra(BlackHoleService.EXTRA_START, true);
                Log.i(TAG, "Start service=" + service);
                context.startService(service);
            }
    }
}
