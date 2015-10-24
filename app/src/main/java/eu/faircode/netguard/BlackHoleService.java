package eu.faircode.netguard;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.VpnService;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.FileInputStream;
import java.io.IOException;

public class BlackHoleService extends VpnService implements Runnable {
    private static final String TAG = "NetGuard.BlackHole";

    private Thread thread;

    public static final String EXTRA_START = "Start";

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "Start");

        if (thread != null)
            thread.interrupt();

        boolean enabled = intent.hasExtra(EXTRA_START) && intent.getBooleanExtra(EXTRA_START, false);

        if (enabled) {
            Log.i(TAG, "Starting");
            thread = new Thread(this, "BlackHoleThread");
            thread.start();
        }

        // TODO: check if start sticky is enough to keep the VPN service alive
        return START_STICKY;
    }

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent.hasExtra(ConnectivityManager.EXTRA_NETWORK_TYPE) &&
                    intent.getIntExtra(ConnectivityManager.EXTRA_NETWORK_TYPE, ConnectivityManager.TYPE_DUMMY) == ConnectivityManager.TYPE_WIFI) {
                Intent service = new Intent(BlackHoleService.this, BlackHoleService.class);
                service.putExtra(BlackHoleService.EXTRA_START, true);
                Log.i(TAG, "Start service=" + service);
                startService(service);
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, intentFilter);
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");
        if (thread != null)
            thread.interrupt();
        unregisterReceiver(connectivityChangedReceiver);
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        Log.i(TAG, "Revoke");
        if (thread != null)
            thread.interrupt();
        super.onRevoke();
    }

    @Override
    public void run() {
        Log.i(TAG, "Run");
        ParcelFileDescriptor pfd = null;
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo ni = cm.getActiveNetworkInfo();
            boolean wifi = (ni != null && ni.getType() == ConnectivityManager.TYPE_WIFI);
            Log.i(TAG, "wifi=" + wifi);

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

            pfd = builder.establish();
            FileInputStream in = new FileInputStream(pfd.getFileDescriptor());

            Log.i(TAG, "Loop start");
            while (!thread.isInterrupted())
                in.skip(32768);
            Log.i(TAG, "Loop exit");
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        } finally {
            if (pfd != null)
                try {
                    pfd.close();
                } catch (IOException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
            thread = null;
            stopSelf();
        }
    }
}
