package eu.faircode.netguard;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.util.Log;

public class Receiver extends BroadcastReceiver {
    private static final String TAG = "NetGuard.Receiver";

    @Override
    public void onReceive(final Context context, Intent intent) {
        Log.i(TAG, "Received " + intent);
        Util.logExtras(TAG, intent);

        if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())) {
            // Remove settings
            if (intent.getBooleanExtra(Intent.EXTRA_DATA_REMOVED, false)) {
                String packageName = intent.getData().getSchemeSpecificPart();
                Log.i(TAG, "Deleting settings package=" + packageName);
                context.getSharedPreferences("wifi", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                context.getSharedPreferences("other", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                context.getSharedPreferences("unused", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                context.getSharedPreferences("roaming", Context.MODE_PRIVATE).edit().remove(packageName).apply();
            }

        } else {
            // Start service
            if (VpnService.prepare(context) == null)
                SinkholeService.start(context);
        }
    }
}