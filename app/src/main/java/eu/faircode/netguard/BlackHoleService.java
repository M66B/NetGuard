package eu.faircode.netguard;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.preference.PreferenceManager;
import android.util.Log;

import java.io.FileInputStream;
import java.io.IOException;

public class BlackHoleService extends VpnService implements Runnable {
    private static final String TAG = "NetGuard.BlackHole";

    private Thread thread = null;
    public static final String EXTRA_COMMAND = "Command";

    public enum Command {start, reload, stop}

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean enabled = prefs.getBoolean("enabled", false);

        Command cmd = (intent == null ? Command.start : (Command) intent.getSerializableExtra(EXTRA_COMMAND));
        Log.i(TAG, "Start intent=" + intent + " command=" + cmd + " enabled=" + enabled + " running=" + (thread != null));

        if (cmd == Command.reload || cmd == Command.stop) {
            if (thread != null) {
                Log.i(TAG, "Stopping thread=" + thread);
                thread.interrupt();
            }
            if (cmd == Command.stop)
                stopSelf();
        }

        if (cmd == Command.start || cmd == Command.reload) {
            if (enabled && (thread == null || thread.isInterrupted())) {
                Log.i(TAG, "Starting");
                thread = new Thread(this, "BlackHoleThread");
                thread.start();
                Log.i(TAG, "Started thread=" + thread);
            }
        }

        return START_STICKY;
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
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, intentFilter);
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");
        if (thread != null) {
            Log.i(TAG, "Interrupt thread=" + thread);
            thread.interrupt();
        }
        unregisterReceiver(connectivityChangedReceiver);
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        Log.i(TAG, "Revoke");
        if (thread != null) {
            Log.i(TAG, "Interrupt thread=" + thread);
            thread.interrupt();
        }
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.edit().putBoolean("enabled", false).apply();
        super.onRevoke();
    }

    @Override
    public synchronized void run() {
        Log.i(TAG, "Run thread=" + Thread.currentThread());
        ParcelFileDescriptor pfd = null;
        try {
            // Check if Wi-Fi connection
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo ni = cm.getActiveNetworkInfo();
            boolean wifi = (ni != null && ni.getType() == ConnectivityManager.TYPE_WIFI);
            Log.i(TAG, "wifi=" + wifi);

            // Build VPN service
            final Builder builder = new Builder();
            builder.setSession("BlackHoleService");
            builder.addAddress("10.1.10.1", 32);
            builder.addRoute("0.0.0.0", 0);
            builder.setBlocking(true);

            // Add list of allowed applications
            for (Rule rule : Rule.getRules(this))
                if (!(wifi ? rule.wifi_blocked : rule.other_blocked)) {
                    Log.i(TAG, "Allowing " + rule.info.packageName);
                    builder.addDisallowedApplication(rule.info.packageName);
                }

            Intent intent = new Intent(this, ActivityMain.class);
            PendingIntent pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);
            builder.setConfigureIntent(pi);

            // Start VPN service
            pfd = builder.establish();

            // Drop all packets
            Log.i(TAG, "Loop start thread=" + Thread.currentThread());
            FileInputStream in = new FileInputStream(pfd.getFileDescriptor());
            while (!Thread.currentThread().isInterrupted() && pfd.getFileDescriptor().valid())
                in.skip(32768);
            Log.i(TAG, "Loop exit thread=" + Thread.currentThread());

        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));

        } finally {
            if (pfd != null)
                try {
                    pfd.close();
                } catch (IOException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
        }
    }
}
