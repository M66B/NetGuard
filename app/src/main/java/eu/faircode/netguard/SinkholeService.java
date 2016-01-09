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

import android.annotation.TargetApi;
import android.app.AlarmManager;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.net.ConnectivityManager;
import android.net.TrafficStats;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.SystemClock;
import android.preference.PreferenceManager;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.NotificationManagerCompat;
import android.support.v4.content.ContextCompat;
import android.support.v4.content.LocalBroadcastManager;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Log;
import android.util.TypedValue;
import android.widget.RemoteViews;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

public class SinkholeService extends VpnService implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Service";

    private State state = State.none;
    private boolean last_connected = false;
    private boolean last_metered = true;
    private boolean last_interactive = false;
    private boolean phone_state = false;
    private Object subscriptionsChangedListener = null;
    private ParcelFileDescriptor vpn = null;
    private Thread receiveThread = null;

    private volatile Looper mServiceLooper;
    private volatile ServiceHandler mServiceHandler;

    private static final int NOTIFY_ENFORCING = 1;
    private static final int NOTIFY_WAITING = 2;
    private static final int NOTIFY_DISABLED = 3;
    private static final int NOTIFY_TRAFFIC = 4;

    public static final String EXTRA_COMMAND = "Command";
    private static final String EXTRA_REASON = "Reason";
    public static final String EXTRA_NETWORK = "Network";
    public static final String EXTRA_UID = "UID";
    public static final String EXTRA_PACKAGE = "Package";
    public static final String EXTRA_BLOCKED = "Blocked";

    private static final int MSG_SERVICE_INTENT = 0;
    private static final int MSG_STATS_START = 1;
    private static final int MSG_STATS_STOP = 2;
    private static final int MSG_STATS_UPDATE = 3;

    private enum State {none, waiting, enforcing, stats}

    public enum Command {run, start, reload, stop, stats, set}

    private static volatile PowerManager.WakeLock wlInstance = null;

    private static final String ACTION_SCREEN_OFF_DELAYED = "eu.faircode.netguard.SCREEN_OFF_DELAYED";

    private native void jni_init();

    private native void jni_decode(byte[] buffer);

    private native void jni_receive(int fd);

    static {
        System.loadLibrary("netguard");
    }

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
                switch (msg.what) {
                    case MSG_SERVICE_INTENT:
                        handleIntent((Intent) msg.obj);
                        break;

                    case MSG_STATS_START:
                        startStats();
                        break;

                    case MSG_STATS_STOP:
                        stopStats();
                        break;

                    case MSG_STATS_UPDATE:
                        updateStats();
                        break;
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                Util.sendCrashReport(ex, SinkholeService.this);
            } finally {
                if (msg.what == MSG_SERVICE_INTENT)
                    try {
                        PowerManager.WakeLock wl = getLock(SinkholeService.this);
                        if (wl.isHeld())
                            wl.release();
                        else
                            Log.w(TAG, "Wakelock under-locked");
                        Log.i(TAG, "Messages=" + hasMessages(0) + " wakelock=" + wlInstance.isHeld());
                    } catch (Exception ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        Util.sendCrashReport(ex, SinkholeService.this);
                    }
            }
        }

        private void handleIntent(Intent intent) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);

            Command cmd = (Command) intent.getSerializableExtra(EXTRA_COMMAND);
            String reason = intent.getStringExtra(EXTRA_REASON);
            Log.i(TAG, "Executing intent=" + intent + " command=" + cmd + " reason=" + reason + " vpn=" + (vpn != null));

            // Listen for phone state changes
            TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null && !phone_state &&
                    Util.hasPhoneStatePermission(SinkholeService.this)) {
                tm.listen(phoneStateListener, PhoneStateListener.LISTEN_DATA_CONNECTION_STATE | PhoneStateListener.LISTEN_SERVICE_STATE);
                phone_state = true;
                Log.i(TAG, "Listening to service state changes");
            }

            // Listen for data SIM changes
            if (subscriptionsChangedListener == null &&
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1 &&
                    Util.hasPhoneStatePermission(SinkholeService.this)) {
                SubscriptionManager sm = SubscriptionManager.from(SinkholeService.this);
                subscriptionsChangedListener = new SubscriptionManager.OnSubscriptionsChangedListener() {
                    @Override
                    public void onSubscriptionsChanged() {
                        Log.i(TAG, "Subscriptions changed");
                        reload(null, "Subscriptions changed", SinkholeService.this);
                    }
                };
                sm.addOnSubscriptionsChangedListener((SubscriptionManager.OnSubscriptionsChangedListener) subscriptionsChangedListener);
                Log.i(TAG, "Listening to subscription changes");
            }

            try {
                switch (cmd) {
                    case run:
                        if (state == State.none) {
                            startForeground(NOTIFY_WAITING, getWaitingNotification());
                            state = State.waiting;
                            Log.d(TAG, "Start foreground state=" + state.toString());
                        }
                        break;

                    case start:
                        if (vpn == null) {
                            if (state != State.none) {
                                Log.d(TAG, "Stop foreground state=" + state.toString());
                                stopForeground(true);
                            }
                            startForeground(NOTIFY_ENFORCING, getEnforcingNotification(0, 0));
                            state = State.enforcing;
                            Log.d(TAG, "Start foreground state=" + state.toString());

                            vpn = startVPN();
                            if (vpn == null)
                                throw new IllegalStateException("VPN start failed");
                            if (prefs.getBoolean("log", false))
                                startReceiving(vpn);
                            removeDisabledNotification();
                        }
                        break;

                    case reload:
                        if (state != State.enforcing) {
                            if (state != State.none) {
                                Log.d(TAG, "Stop foreground state=" + state.toString());
                                stopForeground(true);
                            }
                            startForeground(NOTIFY_ENFORCING, getEnforcingNotification(0, 0));
                            state = State.enforcing;
                            Log.d(TAG, "Start foreground state=" + state.toString());
                        }

                        // Seamless handover
                        ParcelFileDescriptor prev = vpn;
                        vpn = startVPN();
                        if (prev != null && vpn == null) {
                            Log.w(TAG, "Handover failed");
                            stopVPN(prev);
                            prev = null;
                            vpn = startVPN();
                            if (vpn == null)
                                throw new IllegalStateException("Handover failed");
                        }
                        stopReceiving();
                        if (prefs.getBoolean("log", false))
                            startReceiving(vpn);
                        if (prev != null)
                            stopVPN(prev);
                        break;

                    case stop:
                        if (vpn != null) {
                            stopReceiving();
                            stopVPN(vpn);
                            vpn = null;
                        }
                        if (state == State.enforcing) {
                            Log.d(TAG, "Stop foreground state=" + state.toString());
                            stopForeground(true);
                            if (prefs.getBoolean("show_stats", false)) {
                                startForeground(NOTIFY_WAITING, getWaitingNotification());
                                state = State.waiting;
                                Log.d(TAG, "Start foreground state=" + state.toString());
                            } else
                                state = State.none;
                        }
                        break;

                    case stats:
                        stopStats();
                        startStats();
                        break;

                    case set:
                        set(intent);
                        break;
                }

                // Update main view
                Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
                ruleset.putExtra("connected", last_connected);
                ruleset.putExtra("metered", last_metered);
                LocalBroadcastManager.getInstance(SinkholeService.this).sendBroadcast(ruleset);

                // Update widgets
                Widget.updateWidgets(SinkholeService.this);

            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));

                if (Util.isConnected(SinkholeService.this)) {
                    // Disable firewall
                    prefs.edit().putBoolean("enabled", false).apply();
                    Widget.updateWidgets(SinkholeService.this);

                    // Report exception
                    Util.sendCrashReport(ex, SinkholeService.this);
                }
            }
        }

        private boolean stats = false;

        private long t = -1;
        private long tx = -1;
        private long rx = -1;

        private List<Long> gt = new ArrayList<>();
        private List<Float> gtx = new ArrayList<>();
        private List<Float> grx = new ArrayList<>();

        private HashMap<ApplicationInfo, Long> app = new HashMap<>();

        private void startStats() {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
            boolean enabled = (!stats && prefs.getBoolean("show_stats", false));
            Log.i(TAG, "Stats start enabled=" + enabled);
            if (enabled) {
                t = -1;
                tx = -1;
                rx = -1;
                gt.clear();
                gtx.clear();
                grx.clear();
                app.clear();
                stats = true;
                updateStats();
            }
        }

        private void stopStats() {
            Log.i(TAG, "Stats stop");
            stats = false;
            mServiceHandler.removeMessages(MSG_STATS_UPDATE);
            if (state == State.stats) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                stopForeground(true);
                state = State.none;
            } else
                NotificationManagerCompat.from(SinkholeService.this).cancel(NOTIFY_TRAFFIC);
        }

        private void updateStats() {
            RemoteViews remoteViews = new RemoteViews(getPackageName(), R.layout.traffic);
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
            long frequency = Long.parseLong(prefs.getString("stats_frequency", "1000"));
            long samples = Long.parseLong(prefs.getString("stats_samples", "90"));
            float base = Long.parseLong(prefs.getString("stats_base", "5")) * 1000f;

            // Schedule next update
            mServiceHandler.sendEmptyMessageDelayed(MSG_STATS_UPDATE, frequency);

            long ct = SystemClock.elapsedRealtime();

            // Cleanup
            while (gt.size() > 0 && ct - gt.get(0) > samples * 1000) {
                gt.remove(0);
                gtx.remove(0);
                grx.remove(0);
            }

            // Calculate network speed
            float txsec = 0;
            float rxsec = 0;
            long ctx = TrafficStats.getTotalTxBytes();
            long rtx = TrafficStats.getTotalRxBytes();
            if (t > 0 && tx > 0 && rx > 0) {
                float dt = (ct - t) / 1000f;
                txsec = (ctx - tx) / dt;
                rxsec = (rtx - rx) / dt;
                gt.add(ct);
                gtx.add(txsec);
                grx.add(rxsec);
            }

            // Calculate application speeds
            if (prefs.getBoolean("show_top", false)) {
                if (app.size() == 0)
                    for (ApplicationInfo ainfo : getPackageManager().getInstalledApplications(0))
                        app.put(ainfo, TrafficStats.getUidTxBytes(ainfo.uid) + TrafficStats.getUidRxBytes(ainfo.uid));

                else if (t > 0) {
                    TreeMap<Float, ApplicationInfo> mapSpeed = new TreeMap<>(new Comparator<Float>() {
                        @Override
                        public int compare(Float value, Float other) {
                            return -value.compareTo(other);
                        }
                    });
                    float dt = (ct - t) / 1000f;
                    for (ApplicationInfo aInfo : app.keySet()) {
                        long bytes = TrafficStats.getUidTxBytes(aInfo.uid) + TrafficStats.getUidRxBytes(aInfo.uid);
                        float speed = (bytes - app.get(aInfo)) / dt;
                        if (speed > 0) {
                            mapSpeed.put(speed, aInfo);
                            app.put(aInfo, bytes);
                        }
                    }

                    StringBuilder sb = new StringBuilder();
                    int i = 0;
                    for (float s : mapSpeed.keySet()) {
                        if (i++ >= 3)
                            break;
                        if (s < 1000 * 1000)
                            sb.append(getString(R.string.msg_kbsec, s / 1000));
                        else
                            sb.append(getString(R.string.msg_mbsec, s / 1000 / 1000));
                        sb.append(' ');
                        sb.append(getPackageManager().getApplicationLabel(mapSpeed.get(s)).toString());
                        sb.append("\r\n");
                    }
                    if (sb.length() > 0)
                        sb.setLength(sb.length() - 2);
                    remoteViews.setTextViewText(R.id.tvTop, sb.toString());
                }
            }

            t = ct;
            tx = ctx;
            rx = rtx;

            // Create bitmap
            int height = Util.dips2pixels(96, SinkholeService.this);
            int width = Util.dips2pixels(96 * 5, SinkholeService.this);
            Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);

            // Create canvas
            Canvas canvas = new Canvas(bitmap);
            canvas.drawColor(Color.TRANSPARENT);

            // Determine max
            long xmax = 0;
            float ymax = base * 1.5f;
            for (int i = 0; i < gt.size(); i++) {
                long t = gt.get(i);
                float tx = gtx.get(i);
                float rx = grx.get(i);
                if (t > xmax)
                    xmax = t;
                if (tx > ymax)
                    ymax = tx;
                if (rx > ymax)
                    ymax = rx;
            }

            // Build paths
            Path ptx = new Path();
            Path prx = new Path();
            for (int i = 0; i < gtx.size(); i++) {
                float x = width - width * (xmax - gt.get(i)) / 1000f / samples;
                float ytx = height - height * gtx.get(i) / ymax;
                float yrx = height - height * grx.get(i) / ymax;
                if (i == 0) {
                    ptx.moveTo(x, ytx);
                    prx.moveTo(x, yrx);
                } else {
                    ptx.lineTo(x, ytx);
                    prx.lineTo(x, yrx);
                }
            }

            // Build paint
            Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
            paint.setStyle(Paint.Style.STROKE);

            // Draw base line
            paint.setStrokeWidth(Util.dips2pixels(1, SinkholeService.this));
            paint.setColor(Color.GRAY);
            float y = height - height * base / ymax;
            canvas.drawLine(0, y, width, y, paint);

            // Draw paths
            paint.setStrokeWidth(Util.dips2pixels(2, SinkholeService.this));
            paint.setColor(ContextCompat.getColor(SinkholeService.this, R.color.colorSend));
            canvas.drawPath(ptx, paint);
            paint.setColor(ContextCompat.getColor(SinkholeService.this, R.color.colorReceive));
            canvas.drawPath(prx, paint);

            // Update remote view
            remoteViews.setImageViewBitmap(R.id.ivTraffic, bitmap);
            if (txsec < 1000 * 1000)
                remoteViews.setTextViewText(R.id.tvTx, getString(R.string.msg_kbsec, txsec / 1000));
            else
                remoteViews.setTextViewText(R.id.tvTx, getString(R.string.msg_mbsec, txsec / 1000 / 1000));

            if (rxsec < 1000 * 1000)
                remoteViews.setTextViewText(R.id.tvRx, getString(R.string.msg_kbsec, rxsec / 1000));
            else
                remoteViews.setTextViewText(R.id.tvRx, getString(R.string.msg_mbsec, rxsec / 1000 / 1000));

            // Show notification
            Intent main = new Intent(SinkholeService.this, ActivityMain.class);
            PendingIntent pi = PendingIntent.getActivity(SinkholeService.this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

            TypedValue tv = new TypedValue();
            getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
            NotificationCompat.Builder builder = new NotificationCompat.Builder(SinkholeService.this)
                    .setSmallIcon(R.drawable.ic_equalizer_white_24dp)
                    .setContent(remoteViews)
                    .setContentIntent(pi)
                    .setCategory(Notification.CATEGORY_STATUS)
                    .setVisibility(Notification.VISIBILITY_PUBLIC)
                    .setPriority(Notification.PRIORITY_DEFAULT)
                    .setColor(tv.data)
                    .setOngoing(true)
                    .setAutoCancel(false);

            if (state == State.none || state == State.waiting) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                startForeground(NOTIFY_TRAFFIC, builder.build());
                state = State.stats;
                Log.d(TAG, "Start foreground state=" + state.toString());
            } else
                NotificationManagerCompat.from(SinkholeService.this).notify(NOTIFY_TRAFFIC, builder.build());
        }

        private void set(Intent intent) {
            // Get arguments
            int uid = intent.getIntExtra(EXTRA_UID, 0);
            String network = intent.getStringExtra(EXTRA_NETWORK);
            String pkg = intent.getStringExtra(EXTRA_PACKAGE);
            boolean blocked = intent.getBooleanExtra(EXTRA_BLOCKED, false);
            Log.i(TAG, "Set " + pkg + " " + network + "=" + blocked);

            // Get defaults
            SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
            boolean default_wifi = settings.getBoolean("whitelist_wifi", true);
            boolean default_other = settings.getBoolean("whitelist_other", true);

            // Update setting
            SharedPreferences prefs = getSharedPreferences(network, Context.MODE_PRIVATE);
            if (blocked == ("wifi".equals(network) ? default_wifi : default_other))
                prefs.edit().remove(pkg).apply();
            else
                prefs.edit().putBoolean(pkg, blocked).apply();

            // Update notification
            Receiver.notifyNewApplication(uid, SinkholeService.this);

            // Update UI
            Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
            LocalBroadcastManager.getInstance(SinkholeService.this).sendBroadcast(ruleset);
        }
    }

    private ParcelFileDescriptor startVPN() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Check state
        boolean wifi = Util.isWifiActive(this);
        boolean metered = Util.isMeteredNetwork(this);
        boolean useMetered = prefs.getBoolean("use_metered", false);
        Set<String> ssidHomes = prefs.getStringSet("wifi_homes", new HashSet<String>());
        String ssidNetwork = Util.getWifiSSID(this);
        String generation = Util.getNetworkGeneration(this);
        boolean unmetered_2g = prefs.getBoolean("unmetered_2g", false);
        boolean unmetered_3g = prefs.getBoolean("unmetered_3g", false);
        boolean unmetered_4g = prefs.getBoolean("unmetered_4g", false);
        boolean roaming = Util.isRoaming(SinkholeService.this);
        boolean national = prefs.getBoolean("national_roaming", false);
        boolean telephony = Util.hasTelephony(this);

        // Update connected state
        last_connected = Util.isConnected(SinkholeService.this);

        // Update metered state
        if (wifi && (!useMetered || !telephony))
            metered = false;
        if (wifi && ssidHomes.size() > 0 && !ssidHomes.contains(ssidNetwork)) {
            metered = true;
            Log.i(TAG, "Not at home");
        }
        if (unmetered_2g && "2G".equals(generation))
            metered = false;
        if (unmetered_3g && "3G".equals(generation))
            metered = false;
        if (unmetered_4g && "4G".equals(generation))
            metered = false;
        if (!last_connected)
            metered = true;
        last_metered = metered;

        // Update roaming state
        if (roaming && national)
            roaming = Util.isInternational(this);

        Log.i(TAG, "Starting connected=" + last_connected +
                " wifi=" + wifi +
                " home=" + TextUtils.join(",", ssidHomes) +
                " network=" + ssidNetwork +
                " metered=" + metered +
                " telephony=" + telephony +
                " generation=" + generation +
                " roaming=" + roaming +
                " interactive=" + last_interactive);

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
            if ((!blocked || (screen && last_interactive)) && (!metered || !(rule.roaming && roaming))) {
                nAllowed++;
                if (Util.isDebuggable(this))
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
        Notification notification = getEnforcingNotification(nAllowed, nBlocked);
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.notify(NOTIFY_ENFORCING, notification);

        // Build configure intent
        Intent configure = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);

        builder.setBlocking(true);

        // Start VPN service
        return builder.establish();
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

    private void startReceiving(final ParcelFileDescriptor pfd) {
        receiveThread = new Thread(new Runnable() {
            @Override
            public void run() {
                FileInputStream in = null;
                FileOutputStream out = null;
                try {
                    in = new FileInputStream(pfd.getFileDescriptor());
                    out = new FileOutputStream(pfd.getFileDescriptor());

                    ByteBuffer buffer = ByteBuffer.allocate(32767);
                    buffer.order(ByteOrder.BIG_ENDIAN);
                    byte[] bytes = new byte[buffer.limit()];

                    Log.i(TAG, "Start receiving");
                    //jni_receive(pfd.getFd());

                    while (!Thread.currentThread().isInterrupted() &&
                            pfd.getFileDescriptor() != null &&
                            pfd.getFileDescriptor().valid())
                        try {
                            buffer.clear();
                            int length = in.read(bytes);
                            if (length > 0) {
                                buffer.put(bytes, 0, length);
                                buffer.position(0);
                                buffer.limit(length);

                                Packet pkt = new Packet(buffer);
                                Log.i(TAG, "Packet to " + pkt.getDestinationAddress().toString() +
                                        "/" + pkt.getDestinationPort() +
                                        " " + pkt.getFlags() +
                                        " " + pkt.getProtocol());
                                jni_decode(bytes);

                                int connection;
                                if (last_connected)
                                    if (last_metered)
                                        connection = 2;
                                    else
                                        connection = 1;
                                else
                                    connection = 0;

                                int tries = 0;
                                int uid = pkt.getUid();
                                while (uid < 0 && tries < 10) {
                                    Thread.sleep(10);
                                    tries++;
                                    uid = pkt.getUid();
                                    if (uid >= 0)
                                        Log.w(TAG, "Uid found after try=" + tries);
                                }

                                new DatabaseHelper(SinkholeService.this).insertLog(
                                        pkt.version,
                                        pkt.getDestinationAddress().toString(),
                                        pkt.getProtocol(),
                                        pkt.getDestinationPort(),
                                        pkt.getFlags(),
                                        pkt.getUid(),
                                        connection,
                                        last_interactive).close();
                            }
                        } catch (Throwable ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
                    Log.i(TAG, "End receiving");
                } catch (Throwable ex) {
                    if (!Thread.currentThread().isInterrupted() &&
                            pfd.getFileDescriptor() != null &&
                            pfd.getFileDescriptor().valid()) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        Util.sendCrashReport(ex, SinkholeService.this);
                    }
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
        receiveThread.start();
    }

    private void stopReceiving() {
        if (receiveThread != null)
            receiveThread.interrupt();
    }

    private BroadcastReceiver interactiveStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
            int delay = Integer.parseInt(prefs.getString("screen_delay", "0"));
            boolean interactive = Intent.ACTION_SCREEN_ON.equals(intent.getAction());

            AlarmManager am = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
            PendingIntent pi = PendingIntent.getBroadcast(context, 0, new Intent(ACTION_SCREEN_OFF_DELAYED), PendingIntent.FLAG_UPDATE_CURRENT);
            am.cancel(pi);

            if (interactive || delay == 0) {
                last_interactive = interactive;
                reload(null, "interactive state changed", SinkholeService.this);
            } else {
                if (ACTION_SCREEN_OFF_DELAYED.equals(intent.getAction())) {
                    last_interactive = interactive;
                    reload(null, "interactive state changed", SinkholeService.this);
                } else {
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
                        am.set(AlarmManager.RTC_WAKEUP, new Date().getTime() + delay * 60 * 1000L, pi);
                    else
                        am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, new Date().getTime() + delay * 60 * 1000L, pi);
                }
            }

            // Start/stop stats
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            mServiceHandler.sendEmptyMessage(pm.isInteractive() ? MSG_STATS_START : MSG_STATS_STOP);
        }
    };

    private BroadcastReceiver idleStateReceiver = new BroadcastReceiver() {
        @Override
        @TargetApi(Build.VERSION_CODES.M)
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            Log.i(TAG, "device idle=" + pm.isDeviceIdleMode());

            // Reload rules when coming from idle mode
            if (!pm.isDeviceIdleMode())
                reload(null, "idle state changed", SinkholeService.this);
        }
    };

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            // Filter VPN connectivity changes
            int networkType = intent.getIntExtra(ConnectivityManager.EXTRA_NETWORK_TYPE, ConnectivityManager.TYPE_DUMMY);
            if (networkType == ConnectivityManager.TYPE_VPN)
                return;

            // Reload rules
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);
            reload(null, "connectivity changed", SinkholeService.this);
        }
    };

    private PhoneStateListener phoneStateListener = new PhoneStateListener() {
        private String last_generation = null;
        private int last_international = -1;

        @Override
        public void onDataConnectionStateChanged(int state, int networkType) {
            if (state == TelephonyManager.DATA_CONNECTED) {
                String current_generation = Util.getNetworkGeneration(SinkholeService.this);
                Log.i(TAG, "Data connected generation=" + current_generation);

                if (last_generation == null || !last_generation.equals(current_generation)) {
                    Log.i(TAG, "New network generation=" + current_generation);
                    last_generation = current_generation;

                    SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
                    if (prefs.getBoolean("unmetered_2g", false) ||
                            prefs.getBoolean("unmetered_3g", false) ||
                            prefs.getBoolean("unmetered_4g", false))
                        reload("other", "data connection state changed", SinkholeService.this);
                }
            }
        }

        @Override
        public void onServiceStateChanged(ServiceState serviceState) {
            if (serviceState.getState() == ServiceState.STATE_IN_SERVICE) {
                int current_international = (Util.isInternational(SinkholeService.this) ? 1 : 0);
                Log.i(TAG, "In service international=" + current_international);

                if (last_international != current_international) {
                    Log.i(TAG, "New international=" + current_international);
                    last_international = current_international;

                    SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
                    if (prefs.getBoolean("national_roaming", false))
                        reload(null, "service state changed", SinkholeService.this);
                }
            }
        }
    };

    private BroadcastReceiver packageAddedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);
            reload(null, "package added", SinkholeService.this);
        }
    };

    @Override
    public void onCreate() {
        Log.i(TAG, "Create");

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.registerOnSharedPreferenceChangeListener(this);

        Util.setTheme(this);
        super.onCreate();

        HandlerThread thread = new HandlerThread(getString(R.string.app_name) + " handler");
        thread.start();

        mServiceLooper = thread.getLooper();
        mServiceHandler = new ServiceHandler(mServiceLooper);

        // Listen for interactive state changes
        last_interactive = Util.isInteractive(this);
        IntentFilter ifInteractive = new IntentFilter();
        ifInteractive.addAction(Intent.ACTION_SCREEN_ON);
        ifInteractive.addAction(Intent.ACTION_SCREEN_OFF);
        ifInteractive.addAction(ACTION_SCREEN_OFF_DELAYED);
        registerReceiver(interactiveStateReceiver, ifInteractive);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // Listen for idle mode state changes
            IntentFilter ifIdle = new IntentFilter();
            ifIdle.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
            registerReceiver(idleStateReceiver, ifIdle);
        }

        // Listen for connectivity updates
        IntentFilter ifConnectivity = new IntentFilter();
        ifConnectivity.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, ifConnectivity);

        // Listen for added applications
        IntentFilter ifPackage = new IntentFilter();
        ifPackage.addAction(Intent.ACTION_PACKAGE_ADDED);
        ifPackage.addDataScheme("package");
        registerReceiver(packageAddedReceiver, ifPackage);

        // Native
        jni_init();
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        if ("theme".equals(name)) {
            Log.i(TAG, "Theme changed");
            Util.setTheme(this);
            if (state != State.none) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                stopForeground(true);
            }
            if (state == State.enforcing)
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(0, 0));
            else if (state != State.none)
                startForeground(NOTIFY_WAITING, getWaitingNotification());
            Log.d(TAG, "Start foreground state=" + state.toString());
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Keep awake
        getLock(this).acquire();

        // Handle service restart
        if (intent == null) {
            Log.i(TAG, "Restart");

            // Get enabled
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            boolean enabled = prefs.getBoolean("enabled", false);

            // Recreate intent
            intent = new Intent(this, SinkholeService.class);
            intent.putExtra(EXTRA_COMMAND, enabled ? Command.start : Command.stop);
        }

        Command cmd = (Command) intent.getSerializableExtra(EXTRA_COMMAND);
        String reason = intent.getStringExtra(EXTRA_REASON);
        Log.i(TAG, "Start intent=" + intent + " command=" + cmd + " reason=" + reason + " vpn=" + (vpn != null));

        // Queue command
        Message msg = mServiceHandler.obtainMessage();
        msg.arg1 = startId;
        msg.obj = intent;
        msg.what = MSG_SERVICE_INTENT;
        mServiceHandler.sendMessage(msg);

        return START_STICKY;
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

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");

        mServiceLooper.quit();

        unregisterReceiver(interactiveStateReceiver);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            unregisterReceiver(idleStateReceiver);
        unregisterReceiver(connectivityChangedReceiver);
        unregisterReceiver(packageAddedReceiver);

        if (phone_state) {
            TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
            if (tm != null) {
                tm.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE);
                phone_state = false;
            }
        }

        if (subscriptionsChangedListener != null &&
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
            SubscriptionManager sm = SubscriptionManager.from(this);
            sm.removeOnSubscriptionsChangedListener((SubscriptionManager.OnSubscriptionsChangedListener) subscriptionsChangedListener);
            subscriptionsChangedListener = null;
        }

        if (vpn != null) {
            stopReceiving();
            stopVPN(vpn);
            vpn = null;
        }

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.unregisterOnSharedPreferenceChangeListener(this);

        super.onDestroy();
    }

    private Notification getEnforcingNotification(int allowed, int blocked) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_started))
                .setContentIntent(pi)
                .setCategory(Notification.CATEGORY_STATUS)
                .setVisibility(Notification.VISIBILITY_SECRET)
                .setPriority(Notification.PRIORITY_MIN)
                .setColor(tv.data)
                .setOngoing(true)
                .setAutoCancel(false);

        if (allowed > 0 || blocked > 0) {
            NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
            notification.bigText(getString(R.string.msg_started));
            notification.setSummaryText(getString(R.string.msg_packages, allowed, blocked));
            return notification.build();
        } else
            return builder.build();
    }

    private Notification getWaitingNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_waiting))
                .setContentIntent(pi)
                .setCategory(Notification.CATEGORY_STATUS)
                .setVisibility(Notification.VISIBILITY_SECRET)
                .setPriority(Notification.PRIORITY_MIN)
                .setColor(tv.data)
                .setOngoing(true)
                .setAutoCancel(false);
        return builder.build();
    }

    private void showDisabledNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorAccent, tv, true);
        NotificationCompat.Builder notification = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_revoked))
                .setContentIntent(pi)
                .setCategory(Notification.CATEGORY_STATUS)
                .setVisibility(Notification.VISIBILITY_SECRET)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        NotificationManagerCompat.from(this).notify(NOTIFY_DISABLED, notification.build());
    }

    private void removeDisabledNotification() {
        NotificationManagerCompat.from(this).cancel(NOTIFY_DISABLED);
    }

    public static void run(String reason, Context context) {
        Intent intent = new Intent(context, SinkholeService.class);
        intent.putExtra(EXTRA_COMMAND, Command.run);
        intent.putExtra(EXTRA_REASON, reason);
        context.startService(intent);
    }

    public static void start(String reason, Context context) {
        Intent intent = new Intent(context, SinkholeService.class);
        intent.putExtra(EXTRA_COMMAND, Command.start);
        intent.putExtra(EXTRA_REASON, reason);
        context.startService(intent);
    }

    public static void reload(String network, String reason, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        if (prefs.getBoolean("enabled", false)) {
            boolean wifi = Util.isWifiActive(context);
            boolean metered = Util.isMeteredNetwork(context);
            if (wifi && !prefs.getBoolean("use_metered", false))
                metered = false;
            if (network == null || ("wifi".equals(network) ? !metered : metered)) {
                Intent intent = new Intent(context, SinkholeService.class);
                intent.putExtra(EXTRA_COMMAND, Command.reload);
                intent.putExtra(EXTRA_REASON, reason);
                context.startService(intent);
            }
        }
    }

    public static void stop(String reason, Context context) {
        Intent intent = new Intent(context, SinkholeService.class);
        intent.putExtra(EXTRA_COMMAND, Command.stop);
        intent.putExtra(EXTRA_REASON, reason);
        context.startService(intent);
    }

    public static void reloadStats(String reason, Context context) {
        Intent intent = new Intent(context, SinkholeService.class);
        intent.putExtra(EXTRA_COMMAND, Command.stats);
        intent.putExtra(EXTRA_REASON, reason);
        context.startService(intent);
    }
}
