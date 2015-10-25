package eu.faircode.netguard;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.preference.PreferenceManager;
import android.util.Log;

import java.io.IOException;

public class BlackHoleService extends VpnService {
    private static final String TAG = "NetGuard.Service";

    private ParcelFileDescriptor vpn = null;
    public static final String EXTRA_COMMAND = "Command";

    public enum Command {start, reload, stop}

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Get enabled
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean enabled = prefs.getBoolean("enabled", false);

        // Get command
        Command cmd = (intent == null ? Command.start : (Command) intent.getSerializableExtra(EXTRA_COMMAND));
        Log.i(TAG, "Start intent=" + intent + " command=" + cmd + " enabled=" + enabled + " vpn=" + (vpn != null));

        // Process command
        if (cmd == Command.reload || cmd == Command.stop) {
            if (vpn != null)
                vpnStop();
            if (cmd == Command.stop)
                stopSelf();
        }
        if (cmd == Command.start || cmd == Command.reload) {
            if (enabled && vpn == null) {
                Log.i(TAG, "Starting");
                vpnStart();
            }
        }

        return START_STICKY;
    }

    private void vpnStart() {
        Log.i(TAG, "Starting");

        // Check if Wi-Fi
        boolean wifi = Util.isWifiActive(this);
        Log.i(TAG, "wifi=" + wifi);

        // Build VPN service
        final Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name));
        builder.addAddress("10.1.10.1", 32);
        builder.addRoute("0.0.0.0", 0);
        builder.setBlocking(false);

        // Add list of allowed applications
        for (Rule rule : Rule.getRules(this))
            if (!(wifi ? rule.wifi_blocked : rule.other_blocked)) {
                Log.i(TAG, "Allowing " + rule.info.packageName);
                try {
                    builder.addDisallowedApplication(rule.info.packageName);
                } catch (PackageManager.NameNotFoundException ignored) {
                }
            }

        // Build configure intent
        Intent configure = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);

        // Start VPN service
        vpn = builder.establish();
    }

    private void vpnStop() {
        Log.i(TAG, "Stopping");
        try {
            vpn.close();
            vpn = null;
        } catch (IOException ignored) {
        }
    }

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);
            if (intent.hasExtra(ConnectivityManager.EXTRA_NETWORK_TYPE) &&
                    intent.getIntExtra(ConnectivityManager.EXTRA_NETWORK_TYPE, ConnectivityManager.TYPE_DUMMY) == ConnectivityManager.TYPE_WIFI) {
                Intent service = new Intent(BlackHoleService.this, BlackHoleService.class);
                service.putExtra(BlackHoleService.EXTRA_COMMAND, Command.reload);
                startService(service);
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Create");

        // Request connectivity updates
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, intentFilter);
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");

        if (vpn != null)
            vpnStop();

        unregisterReceiver(connectivityChangedReceiver);

        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        Log.i(TAG, "Revoke");

        if (vpn != null)
            vpnStop();

        // Disable firewall
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.edit().putBoolean("enabled", false).apply();

        super.onRevoke();
    }
}
