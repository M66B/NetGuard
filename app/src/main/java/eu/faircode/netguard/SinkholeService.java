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

    Copyright 2015 by Marcel Bokhorst (M66B)
*/

import android.app.Notification;
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
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.preference.PreferenceManager;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.NotificationManagerCompat;
import android.support.v4.content.ContextCompat;
import android.util.Log;
import android.widget.Toast;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class SinkholeService extends VpnService {
    private static final String TAG = "NetGuard.Service";

    private boolean last_roaming;
    private ParcelFileDescriptor vpn = null;
    private boolean debug = false;
    private Thread debugThread = null;

    private volatile Looper mServiceLooper;
    private volatile ServiceHandler mServiceHandler;

    private static final int NOTIFY_FOREGROUND = 1;
    private static final int NOTIFY_DISABLED = 2;

    private static final String EXTRA_COMMAND = "Command";

    private enum Command {start, reload, stop}

    private static volatile PowerManager.WakeLock wlInstance = null;

    synchronized private static PowerManager.WakeLock getLock(Context context) {
        if (wlInstance == null) {
            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            wlInstance = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, context.getString(R.string.app_name) + " wakelock");
            wlInstance.setReferenceCounted(true);
        }
        return wlInstance;
    }

    private final class ServiceHandler extends Handler {
        public ServiceHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            try {
                handleIntent((Intent) msg.obj);
            } finally {
                try {
                    PowerManager.WakeLock wl = getLock(SinkholeService.this);
                    wl.release();
                    Log.i(TAG, "wakelock=" + wl.isHeld());
                } catch (Exception ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    Util.sendCrashReport(ex, SinkholeService.this);
                }
            }
        }

        private void handleIntent(Intent intent) {
            Command cmd = (intent == null ? Command.start : (Command) intent.getSerializableExtra(EXTRA_COMMAND));
            Log.i(TAG, "Executing intent=" + intent + " command=" + cmd + " vpn=" + (vpn != null));
            switch (cmd) {
                case start:
                    if (vpn == null) {
                        startForeground(NOTIFY_FOREGROUND, getForegroundNotification(0, 0));
                        vpn = startVPN();
                        startDebug(vpn);
                        removeDisabledNotification();
                        Widget.updateWidgets(SinkholeService.this);
                    }
                    break;

                case reload:
                    // Seamless handover
                    ParcelFileDescriptor prev = vpn;
                    vpn = startVPN();
                    stopDebug();
                    startDebug(vpn);
                    if (prev != null)
                        stopVPN(prev);
                    break;

                case stop:
                    if (vpn != null) {
                        stopDebug();
                        stopVPN(vpn);
                        vpn = null;
                        stopForeground(true);
                        Widget.updateWidgets(SinkholeService.this);
                        // Don't call stopSelf, since a start can follow
                    }
                    break;
            }
        }
    }

    private ParcelFileDescriptor startVPN() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Check state
        boolean wifi = Util.isWifiActive(this);
        boolean metered = Util.isMeteredNetwork(this);
        boolean interactive = Util.isInteractive(this);
        boolean useMetered = prefs.getBoolean("use_metered", false);
        Log.i(TAG, "Starting wifi=" + wifi +
                " metered=" + metered + "/" + useMetered +
                " roaming=" + last_roaming +
                " interactive=" + interactive);

        if (wifi && !useMetered)
            metered = false;

        // Build VPN service
        final Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name) + " session");
        // TODO: make tunnel parameters configurable
        builder.addAddress("10.1.10.1", 32);
        builder.addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 64);
        builder.addRoute("0.0.0.0", 0);
        builder.addRoute("0:0:0:0:0:0:0:0", 0);

        // Add list of allowed applications
        int nAllowed = 0;
        int nBlocked = 0;
        for (Rule rule : Rule.getRules(true, TAG, this)) {
            boolean blocked = (metered ? rule.other_blocked : rule.wifi_blocked);
            boolean screen = (metered ? rule.screen_other : rule.screen_wifi);
            if ((!blocked || (screen && interactive)) && (!metered || !(rule.roaming && last_roaming))) {
                nAllowed++;
                if (debug)
                    Log.i(TAG, "Allowing " + rule.info.packageName);
                try {
                    builder.addDisallowedApplication(rule.info.packageName);
                } catch (PackageManager.NameNotFoundException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    Util.sendCrashReport(ex, this);
                }
            } else
                nBlocked++;
        }
        Log.i(TAG, "Allowed=" + nAllowed + " blocked=" + nBlocked);

        // Update notification
        Notification notification = getForegroundNotification(nAllowed, nBlocked);
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.notify(NOTIFY_FOREGROUND, notification);

        // Build configure intent
        Intent configure = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);

        if (debug)
            builder.setBlocking(true);

        // Start VPN service
        try {
            ParcelFileDescriptor result = builder.establish();
            if (result == null)
                throw new IllegalStateException("VpnService.Builder.establish returned unexpectedly NULL");
            return result;

        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));

            // Disable firewall
            prefs.edit().putBoolean("enabled", false).apply();

            // Feedback
            Util.sendCrashReport(ex, this);
            Widget.updateWidgets(this);

            return null;
        }
    }

    private void stopVPN(ParcelFileDescriptor pfd) {
        Log.i(TAG, "Stopping");
        try {
            pfd.close();
        } catch (IOException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            Util.sendCrashReport(ex, this);
        }
    }

    private void startDebug(final ParcelFileDescriptor pfd) {
        if (pfd == null || !debug)
            return;

        debugThread = new Thread(new Runnable() {
            @Override
            public void run() {
                FileInputStream in = null;
                FileOutputStream out = null;
                try {
                    in = new FileInputStream(pfd.getFileDescriptor());
                    out = new FileOutputStream(pfd.getFileDescriptor());

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
                            Util.sendCrashReport(ex, SinkholeService.this);
                        }
                    Log.i(TAG, "End receiving");
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    Util.sendCrashReport(ex, SinkholeService.this);
                } finally {
                    try {
                        if (in != null)
                            in.close();
                    } catch (IOException ignored) {
                    }
                    try {
                        if (out != null)
                            out.close();
                    } catch (IOException ignored) {
                    }
                }
            }
        }, getString(R.string.app_name) + " debug");
        debugThread.start();
    }

    private void stopDebug() {
        if (debugThread != null)
            debugThread.interrupt();
    }

    private BroadcastReceiver interactiveStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            // Yield system
            try {
                Thread.sleep(1000);
            } catch (InterruptedException ignored) {
            }

            reload(null, SinkholeService.this);
        }
    };

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            // Get network type
            int networkType = intent.getIntExtra(ConnectivityManager.EXTRA_NETWORK_TYPE, ConnectivityManager.TYPE_DUMMY);
            if (!debug && networkType == ConnectivityManager.TYPE_VPN)
                return;

            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            if (last_roaming != Util.isRoaming(SinkholeService.this)) {
                // Roaming state changed
                last_roaming = !last_roaming;
                Log.i(TAG, "New state roaming=" + last_roaming);
                reload(null, SinkholeService.this);

            } else if (networkType == ConnectivityManager.TYPE_WIFI) {
                // Local network connected/disconnected
                reload(null, SinkholeService.this);
            }
        }
    };

    private BroadcastReceiver packageAddedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);
            reload(null, SinkholeService.this);
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();
        Log.i(TAG, "Create");

        HandlerThread thread = new HandlerThread(getString(R.string.app_name) + " handler");
        thread.start();

        mServiceLooper = thread.getLooper();
        mServiceHandler = new ServiceHandler(mServiceLooper);

        last_roaming = Util.isRoaming(SinkholeService.this);

        // Listen for interactive state changes
        IntentFilter ifInteractive = new IntentFilter();
        ifInteractive.addAction(Intent.ACTION_SCREEN_ON);
        ifInteractive.addAction(Intent.ACTION_SCREEN_OFF);
        registerReceiver(interactiveStateReceiver, ifInteractive);

        // Listen for connectivity updates
        IntentFilter ifConnectivity = new IntentFilter();
        ifConnectivity.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, ifConnectivity);

        // Listen for added applications
        IntentFilter ifPackage = new IntentFilter();
        ifPackage.addAction(Intent.ACTION_PACKAGE_ADDED);
        ifPackage.addDataScheme("package");
        registerReceiver(packageAddedReceiver, ifPackage);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Intent redelivery
        PowerManager.WakeLock wl = getLock(this);
        if (!wl.isHeld())
            wl.acquire();

        // Get command
        final Command cmd = (intent == null ? Command.start : (Command) intent.getSerializableExtra(EXTRA_COMMAND));
        Log.i(TAG, "Start intent=" + intent + " command=" + cmd + " vpn=" + (vpn != null));

        // Queue command
        Message msg = mServiceHandler.obtainMessage();
        msg.arg1 = startId;
        msg.obj = intent;
        mServiceHandler.sendMessage(msg);

        return (cmd == Command.stop ? START_NOT_STICKY : START_STICKY);
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");

        mServiceLooper.quit();

        unregisterReceiver(interactiveStateReceiver);
        unregisterReceiver(connectivityChangedReceiver);
        unregisterReceiver(packageAddedReceiver);

        if (vpn != null) {
            stopDebug();
            stopVPN(vpn);
            vpn = null;
        }

        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        Log.i(TAG, "Revoke");

        // Disable firewall (will result in stop command)
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.edit().putBoolean("enabled", false).apply();

        // Feedback
        showDisabledNotification();
        Widget.updateWidgets(this);

        super.onRevoke();
    }

    private Notification getForegroundNotification(int allowed, int blocked) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_CANCEL_CURRENT);

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_started))
                .setContentIntent(pi)
                .setCategory(Notification.CATEGORY_STATUS)
                .setVisibility(Notification.VISIBILITY_SECRET)
                .setPriority(Notification.PRIORITY_MIN)
                .setColor(ContextCompat.getColor(this, R.color.colorPrimary))
                .setAutoCancel(true);

        if (allowed > 0 || blocked > 0) {
            NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
            notification.bigText(getString(R.string.msg_started));
            notification.setSummaryText(getString(R.string.msg_packages, allowed, blocked));
            return notification.build();
        } else
            return builder.build();
    }

    private void showDisabledNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_CANCEL_CURRENT);

        NotificationCompat.Builder notification = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_revoked))
                .setContentIntent(pi)
                .setCategory(Notification.CATEGORY_STATUS)
                .setVisibility(Notification.VISIBILITY_SECRET)
                .setColor(ContextCompat.getColor(this, R.color.colorAccent))
                .setAutoCancel(true);

        NotificationManagerCompat.from(this).notify(NOTIFY_DISABLED, notification.build());
    }

    private void removeDisabledNotification() {
        NotificationManagerCompat.from(this).cancel(NOTIFY_DISABLED);
    }

    public static void start(Context context) {
        getLock(context).acquire();
        Intent intent = new Intent(context, SinkholeService.class);
        intent.putExtra(EXTRA_COMMAND, Command.start);
        context.startService(intent);
    }

    public static void reload(String network, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        if (prefs.getBoolean("enabled", false)) {
            boolean wifi = Util.isWifiActive(context);
            boolean metered = Util.isMeteredNetwork(context);
            if (wifi && !prefs.getBoolean("use_metered", false))
                metered = false;
            if (network == null || ("wifi".equals(network) ? !metered : metered)) {
                getLock(context).acquire();
                Intent intent = new Intent(context, SinkholeService.class);
                intent.putExtra(EXTRA_COMMAND, Command.reload);
                context.startService(intent);
            }
        }
    }

    public static void stop(Context context) {
        getLock(context).acquire();
        Intent intent = new Intent(context, SinkholeService.class);
        intent.putExtra(EXTRA_COMMAND, Command.stop);
        context.startService(intent);
    }
}
