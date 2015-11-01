package eu.faircode.netguard;

import android.app.NotificationManager;
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
import android.support.v4.app.NotificationCompat;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.Toast;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class SinkholeService extends VpnService {
    private static final String TAG = "NetGuard.Service";

    private ParcelFileDescriptor vpn = null;
    private boolean debug = false;
    private Thread thread = null;

    private static final int NOTIFY_DISABLED = 1;
    private static final String EXTRA_COMMAND = "Command";

    private enum Command {start, reload, stop}

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Get enabled
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        final boolean enabled = prefs.getBoolean("enabled", false);

        // Get command
        final Command cmd = (intent == null ? Command.start : (Command) intent.getSerializableExtra(EXTRA_COMMAND));
        Log.i(TAG, "Start intent=" + intent + " command=" + cmd + " enabled=" + enabled + " vpn=" + (vpn != null));

        // Process command
        new Thread(new Runnable() {
            @Override
            public void run() {
                synchronized (SinkholeService.this) {
                    switch (cmd) {
                        case start:
                            if (enabled && vpn == null) {
                                vpn = startVPN();
                                startDebug(vpn);
                                removeDisabledNotification();
                            }
                            break;

                        case reload:
                            // Seamless handover
                            ParcelFileDescriptor prev = vpn;
                            if (enabled) {
                                vpn = startVPN();
                                stopDebug();
                                startDebug(vpn);
                            }
                            if (prev != null)
                                stopVPN(prev);
                            break;

                        case stop:
                            if (vpn != null) {
                                stopDebug();
                                stopVPN(vpn);
                                vpn = null;
                            }
                            stopSelf();
                            break;
                    }
                }
            }
        }).start();

        return START_STICKY;
    }

    private ParcelFileDescriptor startVPN() {
        Log.i(TAG, "Starting");

        // Check if Wi-Fi
        boolean wifi = Util.isWifiActive(this);
        Log.i(TAG, "wifi=" + wifi);

        // Check if interactive
        boolean interactive = Util.isInteractive(this);
        Log.i(TAG, "interactive=" + interactive);

        // Check roaming
        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        Log.i(TAG, "roaming=" + tm.isNetworkRoaming());

        // Build VPN service
        final Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name));
        builder.addAddress("10.1.10.1", 32);
        builder.addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 64);
        builder.addRoute("0.0.0.0", 0);
        builder.addRoute("0:0:0:0:0:0:0:0", 0);

        // Add list of allowed applications
        for (Rule rule : Rule.getRules(true, TAG, this))
            if (!(wifi ? rule.wifi_blocked : rule.other_blocked) || (rule.unused && interactive)) {
                Log.i(TAG, "Allowing " + rule.info.packageName);
                try {
                    builder.addDisallowedApplication(rule.info.packageName);
                } catch (PackageManager.NameNotFoundException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
            }

        // Build configure intent
        Intent configure = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);

        if (debug)
            builder.setBlocking(true);

        // Start VPN service
        try {
            return builder.establish();

        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));

            // Disable firewall
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean("enabled", false).apply();

            // Feedback
            Util.toast(ex.toString(), Toast.LENGTH_LONG, this);

            return null;
        }
    }

    private void stopVPN(ParcelFileDescriptor pfd) {
        Log.i(TAG, "Stopping");
        try {
            pfd.close();
        } catch (IOException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
    }

    private void startDebug(final ParcelFileDescriptor pfd) {
        if (!debug)
            return;

        thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    FileInputStream in = new FileInputStream(pfd.getFileDescriptor());
                    FileOutputStream out = new FileOutputStream(pfd.getFileDescriptor());

                    ByteBuffer buffer = ByteBuffer.allocate(32767);
                    buffer.order(ByteOrder.BIG_ENDIAN);

                    Log.i(TAG, "Start receiving");
                    while (!Thread.currentThread().isInterrupted() &&
                            pfd.getFileDescriptor() != null &&
                            pfd.getFileDescriptor().valid())
                        try {
                            buffer.clear();
                            int length = in.read(buffer.array());
                            if (length > 0) {
                                buffer.limit(length);
                                Packet pkt = new Packet(buffer);

                                if (pkt.IPv4.protocol == Packet.IPv4Header.TCP && pkt.TCP.SYN) {
                                    int uid = pkt.getUid4();
                                    if (uid < 0)
                                        Log.w(TAG, "uid not found");

                                    String[] pkg = getPackageManager().getPackagesForUid(uid);
                                    if (pkg == null)
                                        pkg = new String[]{uid == 0 ? "root" : "unknown"};

                                    Log.i(TAG, "Connect " + pkt.IPv4.destinationAddress + ":" + pkt.TCP.destinationPort + " uid=" + uid + " pkg=" + pkg[0]);

                                    // Send RST
                                    pkt.swapAddresses();
                                    pkt.TCP.clearFlags();
                                    pkt.TCP.RST = true;
                                    long ack = pkt.TCP.acknowledgementNumber;
                                    pkt.TCP.acknowledgementNumber = (pkt.TCP.sequenceNumber + 1) & 0xFFFFFFFFL;
                                    pkt.TCP.sequenceNumber = (ack + 1) & 0xFFFFFFFFL;
                                    pkt.send(out);
                                }
                            }
                        } catch (Throwable ex) {
                            Log.e(TAG, ex.toString());
                        }
                    Log.i(TAG, "End receiving");
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
            }
        });
        thread.start();
    }

    private void stopDebug() {
        if (thread != null)
            thread.interrupt();
    }

    private BroadcastReceiver packageAddedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);
            reload(null, SinkholeService.this);
        }
    };

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);
            if (intent.hasExtra(ConnectivityManager.EXTRA_NETWORK_TYPE) &&
                    intent.getIntExtra(ConnectivityManager.EXTRA_NETWORK_TYPE, ConnectivityManager.TYPE_DUMMY) == ConnectivityManager.TYPE_WIFI)
                reload(null, SinkholeService.this);
        }
    };

    private BroadcastReceiver interactiveStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);
            reload(null, SinkholeService.this);
        }
    };

    private PhoneStateListener phoneStateListener = new PhoneStateListener() {
        @Override
        public void onServiceStateChanged(ServiceState serviceState) {
            super.onServiceStateChanged(serviceState);
            Log.i(TAG, "Service state changed roaming=" + serviceState.getRoaming());
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Create");

        // Listen for added applications
        IntentFilter ifPackage = new IntentFilter();
        ifPackage.addAction(Intent.ACTION_PACKAGE_ADDED);
        ifPackage.addDataScheme("package");
        registerReceiver(packageAddedReceiver, ifPackage);

        // Listen for connectivity updates
        IntentFilter ifConnectivity = new IntentFilter();
        ifConnectivity.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, ifConnectivity);

        // Listen for interactive state changes
        IntentFilter ifInteractive = new IntentFilter();
        ifInteractive.addAction(Intent.ACTION_SCREEN_ON);
        ifInteractive.addAction(Intent.ACTION_SCREEN_OFF);
        registerReceiver(interactiveStateReceiver, ifInteractive);

        // Listen for service state changes
        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        tm.listen(phoneStateListener, PhoneStateListener.LISTEN_SERVICE_STATE);
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");

        if (vpn != null) {
            stopDebug();
            stopVPN(vpn);
            vpn = null;
        }

        unregisterReceiver(packageAddedReceiver);
        unregisterReceiver(connectivityChangedReceiver);
        unregisterReceiver(interactiveStateReceiver);

        // Listen for service state changes
        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        tm.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE);

        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        Log.i(TAG, "Revoke");

        if (vpn != null) {
            stopDebug();
            stopVPN(vpn);
            vpn = null;
        }

        // Disable firewall
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.edit().putBoolean("enabled", false).apply();

        // Display warning
        showDisabledNotification();

        super.onRevoke();
    }

    private void showDisabledNotification() {
        Intent riMain = new Intent(this, ActivityMain.class);
        PendingIntent piMain = PendingIntent.getActivity(this, 0, riMain, PendingIntent.FLAG_CANCEL_CURRENT);

        NotificationCompat.Builder notification = new NotificationCompat.Builder(this)
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_revoked))
                .setContentIntent(piMain)
                .setAutoCancel(true);

        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        nm.notify(NOTIFY_DISABLED, notification.build());
    }

    private void removeDisabledNotification() {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        nm.cancel(NOTIFY_DISABLED);
    }

    public static void start(Context context) {
        Intent intent = new Intent(context, SinkholeService.class);
        intent.putExtra(EXTRA_COMMAND, Command.start);
        context.startService(intent);
    }

    public static void reload(String network, Context context) {
        if (network == null || ("wifi".equals(network) ? Util.isWifiActive(context) : !Util.isWifiActive(context))) {
            Intent intent = new Intent(context, SinkholeService.class);
            intent.putExtra(EXTRA_COMMAND, Command.reload);
            context.startService(intent);
        }
    }

    public static void stop(Context context) {
        Intent intent = new Intent(context, SinkholeService.class);
        intent.putExtra(EXTRA_COMMAND, Command.stop);
        context.startService(intent);
    }
}
