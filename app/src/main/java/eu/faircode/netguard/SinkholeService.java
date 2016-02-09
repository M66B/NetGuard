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
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Typeface;
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
import android.os.Process;
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
import android.text.Spannable;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.util.Log;
import android.util.TypedValue;
import android.widget.RemoteViews;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class SinkholeService extends VpnService implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Service";

    private State state = State.none;
    private boolean user_foreground = true;
    private boolean last_connected = false;
    private boolean last_metered = true;
    private boolean last_interactive = false;
    private boolean last_tethering = false;
    private boolean last_filter = false;
    private String last_vpn4 = null;
    private String last_vpn6 = null;
    private InetAddress last_dns = null;
    private boolean phone_state = false;
    private Object subscriptionsChangedListener = null;
    private ParcelFileDescriptor vpn = null;

    private Map<String, Boolean> mapHostsBlocked = new HashMap<>();
    private Map<Integer, Boolean> mapUidAllowed = new HashMap<>();
    private Map<Long, Map<InetAddress, Boolean>> mapUidIPFilters = new HashMap<>();
    private Map<Integer, Forward> mapForward = new HashMap<>();

    private volatile Looper mServiceLooper;
    private volatile ServiceHandler mServiceHandler;

    private static final int NOTIFY_ENFORCING = 1;
    private static final int NOTIFY_WAITING = 2;
    private static final int NOTIFY_DISABLED = 3;
    private static final int NOTIFY_AUTOSTART = 4;
    private static final int NOTIFY_ERROR = 5;
    private static final int NOTIFY_TRAFFIC = 6;

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
    private static final int MSG_PACKET = 4;
    private static final int MSG_RR = 5;

    private enum State {none, waiting, enforcing, stats}

    public enum Command {run, start, reload, stop, stats, set}

    private static volatile PowerManager.WakeLock wlInstance = null;

    private static final String ACTION_SCREEN_OFF_DELAYED = "eu.faircode.netguard.SCREEN_OFF_DELAYED";

    private native void jni_init();

    private native void jni_start(int tun, boolean fwd53, int loglevel);

    private native void jni_stop(int tun, boolean clear);

    private native int[] jni_get_session_count();

    private static native void jni_pcap(String name);

    private native void jni_done();

    public static void setPcap(File pcap) {
        jni_pcap(pcap == null ? null : pcap.getAbsolutePath());
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
        private boolean stats = false;
        private long when;

        private long t = -1;
        private long tx = -1;
        private long rx = -1;

        private List<Long> gt = new ArrayList<>();
        private List<Float> gtx = new ArrayList<>();
        private List<Float> grx = new ArrayList<>();

        private HashMap<ApplicationInfo, Long> app = new HashMap<>();

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

                    case MSG_PACKET:
                        log((Packet) msg.obj);
                        break;

                    case MSG_RR:
                        resolved((ResourceRecord) msg.obj);
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
            Log.i(TAG, "Executing intent=" + intent + " command=" + cmd + " reason=" + reason +
                    " vpn=" + (vpn != null) + " user=" + (Process.myUid() / 100000));

            // Check if prepared
            if (cmd == Command.start || cmd == Command.reload)
                if (VpnService.prepare(SinkholeService.this) != null) {
                    Log.w(TAG, "VPN not prepared");
                    prefs.edit().putBoolean("enabled", false).apply();
                    showAutoStartNotification();
                    return;
                }

            // Check if foreground
            if (cmd != Command.stop)
                if (!user_foreground) {
                    Log.i(TAG, "Command " + cmd + "ignored for background user");
                    return;
                }

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
                        SinkholeService.reload(null, "Subscriptions changed", SinkholeService.this);
                    }
                };
                sm.addOnSubscriptionsChangedListener((SubscriptionManager.OnSubscriptionsChangedListener) subscriptionsChangedListener);
                Log.i(TAG, "Listening to subscription changes");
            }

            try {
                switch (cmd) {
                    case run:
                        run();
                        break;

                    case start:
                        start();
                        break;

                    case reload:
                        reload();
                        cleanupDNS();
                        break;

                    case stop:
                        stop();
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

                if (!(ex instanceof IllegalStateException)) {
                    // Disable firewall
                    prefs.edit().putBoolean("enabled", false).apply();
                    Widget.updateWidgets(SinkholeService.this);

                    // Report exception
                    Util.sendCrashReport(ex, SinkholeService.this);
                }
            }
        }

        private void run() {
            if (state == State.none) {
                startForeground(NOTIFY_WAITING, getWaitingNotification());
                state = State.waiting;
                Log.d(TAG, "Start foreground state=" + state.toString());
            }
        }

        private void start() {
            if (vpn == null) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(0, 0, 0));
                state = State.enforcing;
                Log.d(TAG, "Start foreground state=" + state.toString());

                List<Rule> listRule = Rule.getRules(true, TAG, SinkholeService.this);
                List<Rule> listAllowed = getAllowedRules(listRule);

                vpn = startVPN(listAllowed);
                if (vpn == null)
                    throw new IllegalStateException("VPN start failed");

                startNative(vpn, listAllowed);

                removeWarningNotifications();
                updateEnforcingNotification(listAllowed.size(), listRule.size());
            }
        }

        private void reload() {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
            boolean tethering = prefs.getBoolean("tethering", false);
            boolean filter = prefs.getBoolean("filter", false);
            String vpn4 = prefs.getString("vpn4", "10.1.10.1");
            String vpn6 = prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1");
            InetAddress dns = getDns(SinkholeService.this);

            if (state != State.enforcing) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(0, 0, 0));
                state = State.enforcing;
                Log.d(TAG, "Start foreground state=" + state.toString());
            }

            List<Rule> listRule = Rule.getRules(true, TAG, SinkholeService.this);
            List<Rule> listAllowed = getAllowedRules(listRule);

            if (filter &&
                    filter == last_filter &&
                    tethering == last_tethering &&
                    vpn4.equals(last_vpn4) &&
                    vpn6.equals(last_vpn6) &&
                    dns.equals(last_dns)) {
                Log.i(TAG, "Native restart");

                if (vpn != null)
                    stopNative(vpn, false);

                if (vpn == null)
                    vpn = startVPN(listAllowed);
                if (vpn == null)
                    throw new IllegalStateException("VPN start failed");

                startNative(vpn, listAllowed);

            } else {
                Log.i(TAG, "VPN restart");

                // Attempt seamless handover
                ParcelFileDescriptor prev = vpn;
                vpn = startVPN(listAllowed);
                if (prev != null && vpn == null) {
                    Log.w(TAG, "Handover failed");
                    stopVPN(prev);
                    prev = null;
                    vpn = startVPN(listAllowed);
                    if (vpn == null)
                        throw new IllegalStateException("Handover failed");
                }

                if (prev != null) {
                    stopNative(prev, false);
                    stopVPN(prev);
                }
                startNative(vpn, listAllowed);
            }

            updateEnforcingNotification(listAllowed.size(), listRule.size());
        }

        private void stop() {
            if (vpn != null) {
                stopNative(vpn, true);
                stopVPN(vpn);
                vpn = null;
            }
            if (state == State.enforcing) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                stopForeground(true);
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
                if (prefs.getBoolean("show_stats", false)) {
                    startForeground(NOTIFY_WAITING, getWaitingNotification());
                    state = State.waiting;
                    Log.d(TAG, "Start foreground state=" + state.toString());
                } else
                    state = State.none;
            }
        }

        private void startStats() {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
            boolean enabled = (!stats && prefs.getBoolean("show_stats", false));
            Log.i(TAG, "Stats start enabled=" + enabled);
            if (enabled) {
                when = new Date().getTime();
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
            boolean filter = prefs.getBoolean("filter", false);
            boolean show_top = prefs.getBoolean("show_top", false);
            int loglevel = Integer.parseInt(prefs.getString("loglevel", Integer.toString(Log.WARN)));

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
            long ttx = TrafficStats.getTotalTxBytes();
            long trx = TrafficStats.getTotalRxBytes();
            if (filter) {
                ttx -= TrafficStats.getUidTxBytes(Process.myUid());
                trx -= TrafficStats.getUidRxBytes(Process.myUid());
            }
            if (t > 0 && tx > 0 && rx > 0) {
                float dt = (ct - t) / 1000f;
                txsec = (ttx - tx) / dt;
                rxsec = (trx - rx) / dt;
                gt.add(ct);
                gtx.add(txsec);
                grx.add(rxsec);
            }

            // Calculate application speeds
            if (show_top) {
                if (app.size() == 0) {
                    for (ApplicationInfo ainfo : getPackageManager().getInstalledApplications(0))
                        if (ainfo.uid != Process.myUid())
                            app.put(ainfo, TrafficStats.getUidTxBytes(ainfo.uid) + TrafficStats.getUidRxBytes(ainfo.uid));

                } else if (t > 0) {
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
            tx = ttx;
            rx = trx;

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

            if (filter && loglevel <= Log.WARN) {
                int[] count = jni_get_session_count();
                StringBuilder sb = new StringBuilder();
                sb.append(count[0]);
                sb.append('/');
                sb.append(count[1]);
                sb.append('/');
                sb.append(count[2]);
                remoteViews.setTextViewText(R.id.tvSessions, sb.toString());
            } else
                remoteViews.setTextViewText(R.id.tvSessions, "");

            // Show notification
            Intent main = new Intent(SinkholeService.this, ActivityMain.class);
            PendingIntent pi = PendingIntent.getActivity(SinkholeService.this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

            TypedValue tv = new TypedValue();
            getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
            NotificationCompat.Builder builder = new NotificationCompat.Builder(SinkholeService.this)
                    .setWhen(when)
                    .setSmallIcon(R.drawable.ic_equalizer_white_24dp)
                    .setContent(remoteViews)
                    .setContentIntent(pi)
                    .setColor(tv.data)
                    .setOngoing(true)
                    .setAutoCancel(false);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                builder.setCategory(Notification.CATEGORY_STATUS)
                        .setVisibility(Notification.VISIBILITY_PUBLIC);
            }

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

        private void log(Packet packet) {
            // Get settings
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
            boolean log = prefs.getBoolean("log", false);
            boolean log_app = prefs.getBoolean("log_app", false);
            boolean notify = prefs.getBoolean("notify_access", false);
            boolean system = prefs.getBoolean("manage_system", false);

            DatabaseHelper dh = new DatabaseHelper(SinkholeService.this);

            // Get real name
            String dname = dh.getQName(packet.daddr);

            // Traffic log
            if (log)
                dh.insertLog(packet, dname, (last_connected ? last_metered ? 2 : 1 : 0), last_interactive);

            // Application log
            if (log_app && packet.uid >= 0) {
                if (!(packet.protocol == 6 /* TCP */ || packet.protocol == 17 /* UDP */))
                    packet.dport = 0;
                if (dh.updateAccess(packet, dname, -1))
                    if (notify && prefs.getBoolean("notify_" + packet.uid, true) &&
                            (system || !Util.isSystem(packet.uid, SinkholeService.this)))
                        showAccessNotification(packet.uid);
            }

            if (packet.uid < 0 && packet.dport != 53)
                Log.w(TAG, "Unknown application packet=" + packet);

            dh.close();
        }

        private void resolved(ResourceRecord rr) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
            if (prefs.getBoolean("resolved", true))
                new DatabaseHelper(SinkholeService.this).insertDns(rr).close();
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

            // Apply rules
            SinkholeService.reload(null, "notification", SinkholeService.this);

            // Update notification
            Receiver.notifyNewApplication(uid, SinkholeService.this);

            // Update UI
            Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
            LocalBroadcastManager.getInstance(SinkholeService.this).sendBroadcast(ruleset);
        }
    }

    public static InetAddress getDns(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        String sysDns = Util.getDefaultDNS(context);
        String vpnDns = prefs.getString("dns", sysDns);
        Log.i(TAG, "DNS system=" + sysDns + " VPN=" + vpnDns);
        try {
            if (TextUtils.isEmpty(vpnDns.trim()))
                throw new UnknownHostException("dns");
            InetAddress dns = InetAddress.getByName(vpnDns);
            if (dns.isAnyLocalAddress() || dns.isLinkLocalAddress() || dns.isLoopbackAddress())
                throw new UnknownHostException("dns");
            Log.i(TAG, "DNS using=" + dns);
            return dns;
        } catch (Throwable ignored) {
            try {
                InetAddress def = InetAddress.getByName("8.8.8.8");
                Log.i(TAG, "DNS using=" + def);
                return def;
            } catch (UnknownHostException ignored1) {
                return null;
            }
        }
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private ParcelFileDescriptor startVPN(List<Rule> listAllowed) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean tethering = prefs.getBoolean("tethering", false);
        boolean filter = prefs.getBoolean("filter", false);

        last_filter = filter;
        last_tethering = tethering;
        last_vpn4 = prefs.getString("vpn4", "10.1.10.1");
        last_vpn6 = prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1");
        last_dns = getDns(SinkholeService.this);

        // Build VPN service
        final Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name) + " session");

        // VPN address
        Log.i(TAG, "vpn4=" + last_vpn4 + " vpn6=" + last_vpn6);
        builder.addAddress(last_vpn4, 32);
        builder.addAddress(last_vpn6, 64);

        if (filter)
            builder.addDnsServer(last_dns);

        if (tethering) {
            // USB Tethering 192.168.42.x
            // Wi-Fi Tethering 192.168.43.x
            // https://en.wikipedia.org/wiki/IPv4#Special-use_addresses
            for (int r = 1; r <= 223; r++)
                if (r == 192) {
                    for (int s = 1; s <= 255; s++)
                        if (s == 168) {
                            for (int t = 1; t <= 255; t++)
                                if (t != 42 && t != 43)
                                    builder.addRoute(String.format("%d.%d.%d.0", r, s, t), 24);
                        } else
                            builder.addRoute(String.format("%d.%d.0.0", r, s), 16);
                } else if (r != 127)
                    builder.addRoute(String.format("%d.0.0.0", r), 8);
        } else
            builder.addRoute("0.0.0.0", 0);

        builder.addRoute("0:0:0:0:0:0:0:0", 0);

        builder.setMtu(32768);

        // Add list of allowed applications
        if (last_connected && !filter)
            for (Rule rule : listAllowed)
                try {
                    builder.addDisallowedApplication(rule.info.packageName);
                } catch (PackageManager.NameNotFoundException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

        // Build configure intent
        Intent configure = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);

        // Start VPN service
        try {
            return builder.establish();
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            return null;
        }
    }

    private void startNative(ParcelFileDescriptor vpn, List<Rule> listAllowed) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
        boolean log = prefs.getBoolean("log", false);
        boolean filter = prefs.getBoolean("filter", false);

        Log.i(TAG, "Start native log=" + log + " filter=" + filter);

        // Prepare rules
        if (filter) {
            prepareUidAllowed(listAllowed);
            prepareHostsBlocked();
            prepareUidIPFilters();
            prepareForwarding();
        } else
            unprepare();

        if (log || filter) {
            int prio = Integer.parseInt(prefs.getString("loglevel", Integer.toString(Log.WARN)));
            jni_start(vpn.getFd(), mapForward.containsKey(53), prio);
        }

        // Native needs to be started for name resolving
        if (filter)
            new Thread(new Runnable() {
                @Override
                public void run() {
                    updateUidIPFilters();
                }
            }).start();
    }

    private void stopNative(ParcelFileDescriptor vpn, boolean clear) {
        Log.i(TAG, "Stop native clear=" + clear);
        jni_stop(vpn.getFd(), clear);
    }

    private void unprepare() {
        mapUidAllowed.clear();
        mapHostsBlocked.clear();
        mapUidIPFilters.clear();
        mapForward.clear();
    }

    private void prepareUidAllowed(List<Rule> listAllowed) {
        mapUidAllowed.clear();
        for (Rule rule : listAllowed)
            mapUidAllowed.put(rule.info.applicationInfo.uid, true);
    }

    private void prepareHostsBlocked() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
        boolean use_hosts = prefs.getBoolean("use_hosts", false);
        File hosts = new File(getFilesDir(), "hosts.txt");

        mapHostsBlocked.clear();

        if (use_hosts && hosts.exists() && hosts.canRead()) {
            int count = 0;
            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(hosts));
                String line;
                while ((line = br.readLine()) != null) {
                    int hash = line.indexOf('#');
                    if (hash >= 0)
                        line = line.substring(0, hash);
                    line = line.trim();
                    if (line.length() > 0) {
                        String[] words = line.split("\\s+");
                        if (words.length == 2) {
                            count++;
                            mapHostsBlocked.put(words[1], true);
                        } else
                            Log.i(TAG, "Invalid hosts file line: " + line);
                    }
                }
                Log.i(TAG, count + " hosts read");
            } catch (IOException ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            } finally {
                if (br != null)
                    try {
                        br.close();
                    } catch (IOException exex) {
                        Log.e(TAG, exex.toString() + "\n" + Log.getStackTraceString(exex));
                    }
            }
        }
    }

    private void prepareUidIPFilters() {
        Map<Long, Map<InetAddress, Boolean>> map = new HashMap<>();

        DatabaseHelper dh = new DatabaseHelper(SinkholeService.this);

        Cursor cursor = dh.getDns();
        int colUid = cursor.getColumnIndex("uid");
        int colVersion = cursor.getColumnIndex("version");
        int colProtocol = cursor.getColumnIndex("protocol");
        int colDAddr = cursor.getColumnIndex("daddr");
        int colResource = cursor.getColumnIndex("resource");
        int colDPort = cursor.getColumnIndex("dport");
        int colBlock = cursor.getColumnIndex("block");
        while (cursor.moveToNext()) {
            int uid = cursor.getInt(colUid);
            int version = cursor.getInt(colVersion);
            int protocol = cursor.getInt(colProtocol);
            String daddr = cursor.getString(colDAddr);
            String dresource = cursor.getString(colResource);
            int dport = cursor.getInt(colDPort);
            boolean block = (cursor.getInt(colBlock) > 0);

            // long is 64 bits
            // 0..15 uid
            // 16..31 dport
            // 32..39 protocol
            // 40..43 version
            if (!(protocol == 6 /* TCP */ || protocol == 17 /* UDP */))
                dport = 0;
            long key = (version << 40) | (protocol << 32) | (dport << 16) | uid;

            if (!map.containsKey(key))
                map.put(key, new HashMap());

            try {
                map.get(key).put(InetAddress.getByName(dresource), block);
                Log.i(TAG, "Set filter uid=" + uid + " " + daddr + " " + dresource + "/" + dport + "=" + block);
            } catch (UnknownHostException ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }
        cursor.close();

        dh.close();

        synchronized (mapUidIPFilters) {
            mapUidIPFilters = map;
        }
    }

    private void updateUidIPFilters() {
        DatabaseHelper dh = new DatabaseHelper(SinkholeService.this);
        Cursor cursor = dh.getAccess();
        int colDAddr = cursor.getColumnIndex("daddr");
        while (cursor.moveToNext()) {
            String daddr = cursor.getString(colDAddr);
            try {
                // This will result in native callbacks
                InetAddress.getAllByName(daddr);
            } catch (UnknownHostException ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }
        cursor.close();
        dh.close();
    }

    private void prepareForwarding() {
        mapForward.clear();

        DatabaseHelper dh = new DatabaseHelper(SinkholeService.this);

        Cursor cursor = dh.getForwarding();
        int colProtocol = cursor.getColumnIndex("protocol");
        int colDPort = cursor.getColumnIndex("dport");
        int colRAddr = cursor.getColumnIndex("raddr");
        int colRPort = cursor.getColumnIndex("rport");
        int colRUid = cursor.getColumnIndex("ruid");
        while (cursor.moveToNext()) {
            Forward fwd = new Forward();
            fwd.protocol = cursor.getInt(colProtocol);
            fwd.dport = cursor.getInt(colDPort);
            fwd.raddr = cursor.getString(colRAddr);
            fwd.rport = cursor.getInt(colRPort);
            fwd.ruid = cursor.getInt(colRUid);
            mapForward.put(fwd.dport, fwd);
            Log.i(TAG, "Forward " + fwd);
        }
        cursor.close();

        dh.close();
    }

    private void cleanupDNS() {
        // Keep records for a week
        new DatabaseHelper(SinkholeService.this)
                .cleanupDns(new Date().getTime() - 7 * 24 * 3600 * 1000L)
                .close();
    }

    private List<Rule> getAllowedRules(List<Rule> listRule) {
        List<Rule> listAllowed = new ArrayList<>();
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
        boolean tethering = prefs.getBoolean("tethering", false);
        boolean filter = prefs.getBoolean("filter", false);

        // Update connected state
        last_connected = Util.isConnected(SinkholeService.this);

        // Update metered state
        if (wifi && !useMetered)
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
        last_metered = metered;

        // Update roaming state
        if (roaming && national)
            roaming = Util.isInternational(this);

        Log.i(TAG, "Get allowed" +
                " connected=" + last_connected +
                " wifi=" + wifi +
                " home=" + TextUtils.join(",", ssidHomes) +
                " network=" + ssidNetwork +
                " metered=" + metered +
                " generation=" + generation +
                " roaming=" + roaming +
                " interactive=" + last_interactive +
                " tethering=" + tethering +
                " filter=" + filter);

        if (last_connected)
            for (Rule rule : listRule) {
                boolean blocked = (metered ? rule.other_blocked : rule.wifi_blocked);
                boolean screen = (metered ? rule.screen_other : rule.screen_wifi);
                if ((!blocked || (screen && last_interactive)) && (!metered || !(rule.roaming && roaming)))
                    listAllowed.add(rule);
            }

        return listAllowed;
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

    // Called from native code
    private void nativeExit(String reason) {
        Log.w(TAG, "Native exit reason=" + reason);
        if (reason != null) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean("enabled", false).apply();
            showErrorNotification(reason);
        }
    }

    // Called from native code
    private void nativeError(String message) {
        Log.e(TAG, "Native error message=" + message);
    }

    // Called from native code
    private void logPacket(Packet packet) {
        Message msg = mServiceHandler.obtainMessage();
        msg.obj = packet;
        msg.what = MSG_PACKET;
        mServiceHandler.sendMessage(msg);
    }

    // Called from native code
    private void dnsResolved(ResourceRecord rr) {
        Message msg = mServiceHandler.obtainMessage();
        msg.obj = rr;
        msg.what = MSG_RR;
        mServiceHandler.sendMessage(msg);
    }

    // Called from native code
    private boolean isDomainBlocked(String name) {
        return (mapHostsBlocked.containsKey(name) && mapHostsBlocked.get(name));
    }

    // Called from native code
    private Allowed isAddressAllowed(Packet packet) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Allow name resolving
        if (packet.uid == Process.myUid())
            return new Allowed();

        packet.allowed = false;
        if (prefs.getBoolean("filter", false)) {
            if (packet.uid < 0) // unknown
                packet.allowed = true;
            else {
                boolean filtered = false;
                // Only TCP (6) and UDP (17) have port numbers
                int dport = (packet.protocol == 6 || packet.protocol == 17 ? packet.dport : 0);
                long key = (packet.version << 40) | (packet.protocol << 32) | (dport << 16) | packet.uid;

                synchronized (mapUidIPFilters) {
                    if (mapUidIPFilters.containsKey(key))
                        try {
                            InetAddress iaddr = InetAddress.getByName(packet.daddr);
                            Map<InetAddress, Boolean> map = mapUidIPFilters.get(key);
                            if (map != null && map.containsKey(iaddr)) {
                                filtered = true;
                                packet.allowed = !map.get(iaddr);
                                Log.i(TAG, "Filtering " + packet);
                            }
                        } catch (UnknownHostException ex) {
                            Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
                }

                if (!filtered)
                    packet.allowed = (mapUidAllowed.containsKey(packet.uid) && mapUidAllowed.get(packet.uid));
            }
        }

        Allowed allowed = null;
        if (packet.allowed) {
            if (mapForward.containsKey(packet.dport)) {
                Forward fwd = mapForward.get(packet.dport);
                if (fwd.ruid == packet.uid) {
                    allowed = new Allowed();
                } else {
                    allowed = new Allowed(fwd.raddr, fwd.rport);
                    packet.data = "> " + fwd.raddr + ":" + fwd.rport;
                }
            } else
                allowed = new Allowed();
        }

        if (prefs.getBoolean("log", false) || prefs.getBoolean("log_app", false))
            logPacket(packet);

        return allowed;
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
            mServiceHandler.sendEmptyMessage(Util.isInteractive(SinkholeService.this) ? MSG_STATS_START : MSG_STATS_STOP);
        }
    };

    private BroadcastReceiver userReceiver = new BroadcastReceiver() {
        @Override
        @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR1)
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            user_foreground = Intent.ACTION_USER_FOREGROUND.equals(intent.getAction());
            Log.i(TAG, "User foreground=" + user_foreground + " user=" + (Process.myUid() / 100000));

            if (user_foreground) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(SinkholeService.this);
                if (prefs.getBoolean("enabled", false)) {
                    // Allow service of background user to stop
                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException ignored) {
                    }

                    start("foreground", SinkholeService.this);
                }
            } else
                stop("background", SinkholeService.this);
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
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                int networkType = intent.getIntExtra(ConnectivityManager.EXTRA_NETWORK_TYPE, ConnectivityManager.TYPE_DUMMY);
                if (networkType == ConnectivityManager.TYPE_VPN)
                    return;
            }

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

        // Native init
        jni_init();
        boolean pcap = prefs.getBoolean("pcap", false);
        setPcap(pcap ? new File(getCacheDir(), "netguard.pcap") : null);

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

        // Listen for user switches
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            IntentFilter ifUser = new IntentFilter();
            ifUser.addAction(Intent.ACTION_USER_BACKGROUND);
            ifUser.addAction(Intent.ACTION_USER_FOREGROUND);
            registerReceiver(userReceiver, ifUser);
        }

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
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(0, 0, 0));
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
        Log.i(TAG, "Start intent=" + intent + " command=" + cmd + " reason=" + reason +
                " vpn=" + (vpn != null) + " user=" + (Process.myUid() / 100000));

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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1)
            unregisterReceiver(userReceiver);
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

        try {
            if (vpn != null) {
                stopNative(vpn, true);
                stopVPN(vpn);
                vpn = null;
            }
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        jni_done();

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.unregisterOnSharedPreferenceChangeListener(this);

        super.onDestroy();
    }

    private Notification getEnforcingNotification(int allowed, int blocked, int hosts) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_started))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(true)
                .setAutoCancel(false);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_STATUS)
                    .setVisibility(Notification.VISIBILITY_SECRET)
                    .setPriority(Notification.PRIORITY_MIN);
        }

        if (allowed > 0 || blocked > 0 || hosts > 0) {
            NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
            notification.bigText(getString(R.string.msg_started));
            if (Util.isPlayStoreInstall(this))
                notification.setSummaryText(getString(R.string.msg_packages, allowed, blocked));
            else
                notification.setSummaryText(getString(R.string.msg_hosts, allowed, blocked, hosts));
            return notification.build();
        } else
            return builder.build();
    }

    private void updateEnforcingNotification(int allowed, int total) {
        // Update notification
        Notification notification = getEnforcingNotification(allowed, total - allowed, mapHostsBlocked.size());
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        nm.notify(NOTIFY_ENFORCING, notification);
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
                .setColor(tv.data)
                .setOngoing(true)
                .setAutoCancel(false);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_STATUS)
                    .setVisibility(Notification.VISIBILITY_SECRET)
                    .setPriority(Notification.PRIORITY_MIN);
        }

        return builder.build();
    }

    private void showDisabledNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_revoked))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_STATUS)
                    .setVisibility(Notification.VISIBILITY_SECRET);
        }

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_revoked));

        NotificationManagerCompat.from(this).notify(NOTIFY_DISABLED, notification.build());
    }

    private void showAutoStartNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        main.putExtra(ActivityMain.EXTRA_APPROVE, true);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_autostart))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_STATUS)
                    .setVisibility(Notification.VISIBILITY_SECRET);
        }

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_autostart));

        NotificationManagerCompat.from(this).notify(NOTIFY_AUTOSTART, notification.build());
    }

    private void showErrorNotification(String reason) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_error))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_STATUS)
                    .setVisibility(Notification.VISIBILITY_SECRET);
        }

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_error));
        notification.setSummaryText(reason);

        NotificationManagerCompat.from(this).notify(NOTIFY_ERROR, notification.build());
    }

    private void showAccessNotification(int uid) {
        String name = TextUtils.join(", ", Util.getApplicationNames(uid, SinkholeService.this));

        Intent main = new Intent(SinkholeService.this, ActivityMain.class);
        main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
        PendingIntent pi = PendingIntent.getActivity(SinkholeService.this, uid + 10000, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        int colorOn = tv.data;
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        int colorOff = tv.data;

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this)
                .setSmallIcon(R.drawable.ic_cloud_upload_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_access, name))
                .setContentIntent(pi)
                .setColor(colorOff)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            builder.setCategory(Notification.CATEGORY_STATUS)
                    .setVisibility(Notification.VISIBILITY_SECRET);
        }

        DateFormat df = new SimpleDateFormat("dd HH:mm");

        NotificationCompat.InboxStyle notification = new NotificationCompat.InboxStyle(builder);
        String sname = getString(R.string.msg_access, name);
        int pos = sname.indexOf(name);
        Spannable sp = new SpannableString(sname);
        sp.setSpan(new StyleSpan(Typeface.BOLD), pos, pos + name.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        notification.addLine(sp);

        DatabaseHelper dh = new DatabaseHelper(SinkholeService.this);
        Cursor cursor = dh.getAccessUnset(uid);
        int colDAddr = cursor.getColumnIndex("daddr");
        int colTime = cursor.getColumnIndex("time");
        int colAllowed = cursor.getColumnIndex("allowed");
        while (cursor.moveToNext()) {
            StringBuilder sb = new StringBuilder();
            sb.append(df.format(cursor.getLong(colTime))).append(' ');

            String daddr = cursor.getString(colDAddr);
            sb.append(daddr);

            int allowed = cursor.getInt(colAllowed);
            if (allowed >= 0) {
                pos = sb.indexOf(daddr);
                sp = new SpannableString(sb);
                ForegroundColorSpan fgsp = new ForegroundColorSpan(allowed > 0 ? colorOn : colorOff);
                sp.setSpan(fgsp, pos, pos + daddr.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            }
            notification.addLine(sp);
        }
        cursor.close();
        dh.close();

        NotificationManagerCompat.from(this).notify(uid + 10000, notification.build());
    }

    private void removeWarningNotifications() {
        NotificationManagerCompat.from(this).cancel(NOTIFY_DISABLED);
        NotificationManagerCompat.from(this).cancel(NOTIFY_ERROR);
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
