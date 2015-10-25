package eu.faircode.netguard;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.util.Log;

public class Receiver extends BroadcastReceiver {
    private static final String TAG = "NetGuard.Receiver";

    @Override
    public void onReceive(final Context context, Intent intent) {
        Log.i(TAG, "Received " + intent);
        Util.logExtras(TAG, intent);

        // Start service
        if (VpnService.prepare(context) == null) {
            Intent service = new Intent(context, BlackHoleService.class);
            service.putExtra(BlackHoleService.EXTRA_COMMAND, BlackHoleService.Command.start);
            context.startService(service);
        }
    }
}