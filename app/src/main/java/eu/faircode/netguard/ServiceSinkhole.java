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

    Copyright 2015-2017 by Marcel Bokhorst (M66B)
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
import android.content.res.Configuration;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.NetworkRequest;
import android.net.TrafficStats;
import android.net.Uri;
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
import android.telephony.TelephonyManager;
import android.text.Spannable;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.util.Log;
import android.util.TypedValue;
import android.widget.RemoteViews;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.net.ssl.HttpsURLConnection;

public class ServiceSinkhole extends VpnService implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Service";

    private boolean registeredPowerSave = false;
    private boolean registeredUser = false;
    private boolean registeredIdleState = false;
    private boolean registeredConnectivityChanged = false;
    private boolean registeredPackageChanged = false;

    private boolean phone_state = false;
    private Object networkCallback = null;

    private boolean registeredInteractiveState = false;
    private PhoneStateListener callStateListener = null;

    private State state = State.none;
    private boolean user_foreground = true;
    private boolean last_connected = false;
    private boolean last_metered = true;
    private boolean last_interactive = false;
    private boolean powersaving = false;

    private int last_allowed = -1;
    private int last_blocked = -1;
    private int last_hosts = -1;

    private long jni_context = 0;
    private Thread tunnelThread = null;
    private ServiceSinkhole.Builder last_builder = null;
    private ParcelFileDescriptor vpn = null;
    private boolean temporarilyStopped = false;

    private long last_hosts_modified = 0;
    private Map<String, Boolean> mapHostsBlocked = new HashMap<>();
    private Map<Integer, Boolean> mapUidAllowed = new HashMap<>();
    private Map<Integer, Integer> mapUidKnown = new HashMap<>();
    private final Map<Long, Map<InetAddress, IPRule>> mapUidIPFilters = new HashMap<>();
    private Map<Integer, Forward> mapForward = new HashMap<>();
    private Map<Integer, Boolean> mapNotify = new HashMap<>();
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    private volatile Looper commandLooper;
    private volatile Looper logLooper;
    private volatile Looper statsLooper;
    private volatile CommandHandler commandHandler;
    private volatile LogHandler logHandler;
    private volatile StatsHandler statsHandler;

    private static final int NOTIFY_ENFORCING = 1;
    private static final int NOTIFY_WAITING = 2;
    private static final int NOTIFY_DISABLED = 3;
    private static final int NOTIFY_AUTOSTART = 4;
    private static final int NOTIFY_ERROR = 5;
    private static final int NOTIFY_TRAFFIC = 6;
    private static final int NOTIFY_UPDATE = 7;
    public static final int NOTIFY_EXTERNAL = 8;
    public static final int NOTIFY_DOWNLOAD = 9;

    public static final String EXTRA_COMMAND = "Command";
    private static final String EXTRA_REASON = "Reason";
    public static final String EXTRA_NETWORK = "Network";
    public static final String EXTRA_UID = "UID";
    public static final String EXTRA_PACKAGE = "Package";
    public static final String EXTRA_BLOCKED = "Blocked";
    public static final String EXTRA_INTERACTIVE = "Interactive";
    public static final String EXTRA_TEMPORARY = "Temporary";

    private static final int MSG_STATS_START = 1;
    private static final int MSG_STATS_STOP = 2;
    private static final int MSG_STATS_UPDATE = 3;
    private static final int MSG_PACKET = 4;
    private static final int MSG_USAGE = 5;

    private enum State {none, waiting, enforcing, stats}

    public enum Command {run, start, reload, stop, stats, set, householding, watchdog}

    private static volatile PowerManager.WakeLock wlInstance = null;

    private ExecutorService executor = Executors.newCachedThreadPool();

    private static final String ACTION_HOUSE_HOLDING = "eu.faircode.netguard.HOUSE_HOLDING";
    private static final String ACTION_SCREEN_OFF_DELAYED = "eu.faircode.netguard.SCREEN_OFF_DELAYED";
    private static final String ACTION_WATCHDOG = "eu.faircode.netguard.WATCHDOG";

    private native long jni_init(int sdk);

    private native void jni_start(long context, int loglevel);

    private native void jni_run(long context, int tun, boolean fwd53, int rcode);

    private native void jni_stop(long context);

    private native void jni_clear(long context);

    private native int jni_get_mtu();

    private native int[] jni_get_stats(long context);

    private static native void jni_pcap(String name, int record_size, int file_size);

    private native void jni_socks5(String addr, int port, String username, String password);

    private native void jni_done(long context);

    public static void setPcap(boolean enabled, Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        int record_size = 64;
        try {
            String r = prefs.getString("pcap_record_size", null);
            if (TextUtils.isEmpty(r))
                r = "64";
            record_size = Integer.parseInt(r);
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        int file_size = 2 * 1024 * 1024;
        try {
            String f = prefs.getString("pcap_file_size", null);
            if (TextUtils.isEmpty(f))
                f = "2";
            file_size = Integer.parseInt(f) * 1024 * 1024;
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        File pcap = (enabled ? new File(context.getDir("data", MODE_PRIVATE), "netguard.pcap") : null);
        jni_pcap(pcap == null ? null : pcap.getAbsolutePath(), record_size, file_size);
    }

    synchronized private static PowerManager.WakeLock getLock(Context context) {
        if (wlInstance == null) {
            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            wlInstance = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, context.getString(R.string.app_name) + " wakelock");
            wlInstance.setReferenceCounted(true);
        }
        return wlInstance;
    }

    synchronized private static void releaseLock(Context context) {
        if (wlInstance != null) {
            while (wlInstance.isHeld())
                wlInstance.release();
            wlInstance = null;
        }
    }

    private final class CommandHandler extends Handler {
        public int queue = 0;

        public CommandHandler(Looper looper) {
            super(looper);
        }

        private void reportQueueSize() {
            Intent ruleset = new Intent(ActivityMain.ACTION_QUEUE_CHANGED);
            ruleset.putExtra(ActivityMain.EXTRA_SIZE, queue);
            LocalBroadcastManager.getInstance(ServiceSinkhole.this).sendBroadcast(ruleset);
        }

        public void queue(Intent intent) {
            synchronized (this) {
                queue++;
                reportQueueSize();
            }
            Command cmd = (Command) intent.getSerializableExtra(EXTRA_COMMAND);
            Message msg = commandHandler.obtainMessage();
            msg.obj = intent;
            msg.what = cmd.ordinal();
            commandHandler.sendMessage(msg);
        }

        @Override
        public void handleMessage(Message msg) {
            try {
                synchronized (ServiceSinkhole.this) {
                    handleIntent((Intent) msg.obj);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            } finally {
                synchronized (this) {
                    queue--;
                    reportQueueSize();
                }
                try {
                    PowerManager.WakeLock wl = getLock(ServiceSinkhole.this);
                    if (wl.isHeld())
                        wl.release();
                    else
                        Log.w(TAG, "Wakelock under-locked");
                    Log.i(TAG, "Messages=" + hasMessages(0) + " wakelock=" + wlInstance.isHeld());
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
            }
        }

        private void handleIntent(Intent intent) {
            final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);

            Command cmd = (Command) intent.getSerializableExtra(EXTRA_COMMAND);
            String reason = intent.getStringExtra(EXTRA_REASON);
            Log.i(TAG, "Executing intent=" + intent + " command=" + cmd + " reason=" + reason +
                    " vpn=" + (vpn != null) + " user=" + (Process.myUid() / 100000));

            // Check if foreground
            if (cmd != Command.stop)
                if (!user_foreground) {
                    Log.i(TAG, "Command " + cmd + " ignored for background user");
                    return;
                }

            // Handle temporary stop
            if (cmd == Command.stop)
                temporarilyStopped = intent.getBooleanExtra(EXTRA_TEMPORARY, false);
            else if (cmd == Command.start)
                temporarilyStopped = false;
            else if (cmd == Command.reload && temporarilyStopped) {
                // Prevent network/interactive changes from restarting the VPN
                Log.i(TAG, "Command " + cmd + " ignored because of temporary stop");
                return;
            }

            // Optionally listen for interactive state changes
            if (prefs.getBoolean("screen_on", true)) {
                if (!registeredInteractiveState) {
                    Log.i(TAG, "Starting listening for interactive state changes");
                    last_interactive = Util.isInteractive(ServiceSinkhole.this);
                    IntentFilter ifInteractive = new IntentFilter();
                    ifInteractive.addAction(Intent.ACTION_SCREEN_ON);
                    ifInteractive.addAction(Intent.ACTION_SCREEN_OFF);
                    ifInteractive.addAction(ACTION_SCREEN_OFF_DELAYED);
                    registerReceiver(interactiveStateReceiver, ifInteractive);
                    registeredInteractiveState = true;
                }
            } else {
                if (registeredInteractiveState) {
                    Log.i(TAG, "Stopping listening for interactive state changes");
                    unregisterReceiver(interactiveStateReceiver);
                    registeredInteractiveState = false;
                }
            }

            // Optionally listen for call state changes
            TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
            if (prefs.getBoolean("disable_on_call", false)) {
                if (tm != null && callStateListener == null && Util.hasPhoneStatePermission(ServiceSinkhole.this)) {
                    Log.i(TAG, "Starting listening for call states");
                    PhoneStateListener listener = new PhoneStateListener() {
                        @Override
                        public void onCallStateChanged(int state, String incomingNumber) {
                            Log.i(TAG, "New call state=" + state);
                            if (prefs.getBoolean("enabled", false))
                                if (state == TelephonyManager.CALL_STATE_IDLE)
                                    ServiceSinkhole.start("call state", ServiceSinkhole.this);
                                else
                                    ServiceSinkhole.stop("call state", ServiceSinkhole.this, true);
                        }
                    };
                    tm.listen(listener, PhoneStateListener.LISTEN_CALL_STATE);
                    callStateListener = listener;
                }
            } else {
                if (tm != null && callStateListener != null) {
                    Log.i(TAG, "Stopping listening for call states");
                    tm.listen(callStateListener, PhoneStateListener.LISTEN_NONE);
                    callStateListener = null;
                }
            }

            // Watchdog
            if (cmd == Command.start || cmd == Command.reload || cmd == Command.stop) {
                Intent watchdogIntent = new Intent(ServiceSinkhole.this, ServiceSinkhole.class);
                watchdogIntent.setAction(ACTION_WATCHDOG);
                PendingIntent pi;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                    pi = PendingIntent.getForegroundService(ServiceSinkhole.this, 1, watchdogIntent, PendingIntent.FLAG_UPDATE_CURRENT);
                else
                    pi = PendingIntent.getService(ServiceSinkhole.this, 1, watchdogIntent, PendingIntent.FLAG_UPDATE_CURRENT);

                AlarmManager am = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
                am.cancel(pi);

                if (cmd != Command.stop) {
                    int watchdog = Integer.parseInt(prefs.getString("watchdog", "0"));
                    if (watchdog > 0) {
                        Log.i(TAG, "Watchdog " + watchdog + " minutes");
                        am.setInexactRepeating(AlarmManager.RTC, SystemClock.elapsedRealtime() + watchdog * 60 * 1000, watchdog * 60 * 1000, pi);
                    }
                }
            }

            try {
                switch (cmd) {
                    case run:
                        break;

                    case start:
                        start();
                        break;

                    case reload:
                        reload(intent.getBooleanExtra(EXTRA_INTERACTIVE, false));
                        break;

                    case stop:
                        stop(temporarilyStopped);
                        break;

                    case stats:
                        statsHandler.sendEmptyMessage(MSG_STATS_STOP);
                        statsHandler.sendEmptyMessage(MSG_STATS_START);
                        break;

                    case householding:
                        householding(intent);
                        break;

                    case watchdog:
                        watchdog(intent);
                        break;

                    default:
                        Log.e(TAG, "Unknown command=" + cmd);
                }

                if (cmd == Command.start || cmd == Command.reload || cmd == Command.stop) {
                    // Update main view
                    Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
                    ruleset.putExtra(ActivityMain.EXTRA_CONNECTED, cmd == Command.stop ? false : last_connected);
                    ruleset.putExtra(ActivityMain.EXTRA_METERED, cmd == Command.stop ? false : last_metered);
                    LocalBroadcastManager.getInstance(ServiceSinkhole.this).sendBroadcast(ruleset);

                    // Update widgets
                    WidgetMain.updateWidgets(ServiceSinkhole.this);
                }

                // Stop service if needed
                if (!commandHandler.hasMessages(Command.start.ordinal()) &&
                        !commandHandler.hasMessages(Command.reload.ordinal()) &&
                        !prefs.getBoolean("enabled", false) &&
                        !prefs.getBoolean("show_stats", false))
                    stopForeground(true);

            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));

                if (cmd == Command.start || cmd == Command.reload) {
                    if (VpnService.prepare(ServiceSinkhole.this) == null) {
                        Log.w(TAG, "VPN not prepared connected=" + last_connected);
                        if (last_connected) {
                            showAutoStartNotification();
                            if (!Util.isPlayStoreInstall(ServiceSinkhole.this))
                                showErrorNotification(ex.toString());
                        }
                        // Retried on connectivity change
                    } else {
                        showErrorNotification(ex.toString());

                        // Disable firewall
                        if (!(ex instanceof StartFailedException)) {
                            prefs.edit().putBoolean("enabled", false).apply();
                            WidgetMain.updateWidgets(ServiceSinkhole.this);
                        }
                    }
                } else
                    showErrorNotification(ex.toString());
            }
        }

        private void start() {
            if (vpn == null) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(-1, -1, -1));
                state = State.enforcing;
                Log.d(TAG, "Start foreground state=" + state.toString());

                List<Rule> listRule = Rule.getRules(true, ServiceSinkhole.this);
                List<Rule> listAllowed = getAllowedRules(listRule);

                last_builder = getBuilder(listAllowed, listRule);
                vpn = startVPN(last_builder);
                if (vpn == null)
                    throw new StartFailedException(getString((R.string.msg_start_failed)));

                startNative(vpn, listAllowed, listRule);

                removeWarningNotifications();
                updateEnforcingNotification(listAllowed.size(), listRule.size());
            }
        }

        private void reload(boolean interactive) {
            List<Rule> listRule = Rule.getRules(true, ServiceSinkhole.this);

            // Check if rules needs to be reloaded
            if (interactive) {
                boolean process = false;
                for (Rule rule : listRule) {
                    boolean blocked = (last_metered ? rule.other_blocked : rule.wifi_blocked);
                    boolean screen = (last_metered ? rule.screen_other : rule.screen_wifi);
                    if (blocked && screen) {
                        process = true;
                        break;
                    }
                }
                if (!process) {
                    Log.i(TAG, "No changed rules on interactive state change");
                    return;
                }
            }

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            boolean clear = prefs.getBoolean("clear_onreload", false);

            if (state != State.enforcing) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(-1, -1, -1));
                state = State.enforcing;
                Log.d(TAG, "Start foreground state=" + state.toString());
            }

            List<Rule> listAllowed = getAllowedRules(listRule);
            ServiceSinkhole.Builder builder = getBuilder(listAllowed, listRule);

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) {
                last_builder = builder;
                Log.i(TAG, "Legacy restart");

                if (vpn != null) {
                    stopNative(vpn, clear);
                    stopVPN(vpn);
                    vpn = null;
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ignored) {
                    }
                }
                vpn = startVPN(last_builder);

            } else {
                if (vpn != null && prefs.getBoolean("filter", false) && builder.equals(last_builder)) {
                    Log.i(TAG, "Native restart");
                    stopNative(vpn, clear);

                } else {
                    last_builder = builder;
                    Log.i(TAG, "VPN restart");

                    // Attempt seamless handover
                    ParcelFileDescriptor prev = vpn;
                    vpn = startVPN(builder);

                    if (prev != null && vpn == null) {
                        Log.w(TAG, "Handover failed");
                        stopNative(prev, clear);
                        stopVPN(prev);
                        prev = null;
                        try {
                            Thread.sleep(3000);
                        } catch (InterruptedException ignored) {
                        }
                        vpn = startVPN(last_builder);
                        if (vpn == null)
                            throw new IllegalStateException("Handover failed");
                    }

                    if (prev != null) {
                        stopNative(prev, clear);
                        stopVPN(prev);
                    }
                }
            }

            if (vpn == null)
                throw new StartFailedException(getString((R.string.msg_start_failed)));

            startNative(vpn, listAllowed, listRule);

            removeWarningNotifications();
            updateEnforcingNotification(listAllowed.size(), listRule.size());
        }

        private void stop(boolean temporary) {
            if (vpn != null) {
                stopNative(vpn, true);
                stopVPN(vpn);
                vpn = null;
                unprepare();
            }
            if (state == State.enforcing && !temporary) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                last_allowed = -1;
                last_blocked = -1;
                last_hosts = -1;

                stopForeground(true);

                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                if (prefs.getBoolean("show_stats", false)) {
                    startForeground(NOTIFY_WAITING, getWaitingNotification());
                    state = State.waiting;
                    Log.d(TAG, "Start foreground state=" + state.toString());
                } else {
                    state = State.none;
                    stopSelf();
                }
            }
        }

        private void householding(Intent intent) {
            // Keep log records for three days
            DatabaseHelper.getInstance(ServiceSinkhole.this).cleanupLog(new Date().getTime() - 3 * 24 * 3600 * 1000L);

            // Clear expired DNS records
            DatabaseHelper.getInstance(ServiceSinkhole.this).cleanupDns();

            // Check for update
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            if (!Util.isPlayStoreInstall(ServiceSinkhole.this) && prefs.getBoolean("update_check", true))
                checkUpdate();
        }

        private void watchdog(Intent intent) {
            if (vpn == null) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                if (prefs.getBoolean("enabled", false)) {
                    Log.e(TAG, "Service was killed");
                    start();
                }
            }
        }

        private void checkUpdate() {
            StringBuilder json = new StringBuilder();
            HttpsURLConnection urlConnection = null;
            try {
                URL url = new URL("https://api.github.com/repos/M66B/NetGuard/releases/latest");
                urlConnection = (HttpsURLConnection) url.openConnection();
                BufferedReader br = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));

                String line;
                while ((line = br.readLine()) != null)
                    json.append(line);

            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            } finally {
                if (urlConnection != null)
                    urlConnection.disconnect();
            }

            try {
                JSONObject jroot = new JSONObject(json.toString());
                if (jroot.has("tag_name") && jroot.has("html_url") && jroot.has("assets")) {
                    String url = jroot.getString("html_url");
                    JSONArray jassets = jroot.getJSONArray("assets");
                    if (jassets.length() > 0) {
                        JSONObject jasset = jassets.getJSONObject(0);
                        if (jasset.has("name")) {
                            String version = jroot.getString("tag_name");
                            String name = jasset.getString("name");
                            Log.i(TAG, "Tag " + version + " name " + name + " url " + url);

                            Version current = new Version(Util.getSelfVersionName(ServiceSinkhole.this));
                            Version available = new Version(version);
                            if (current.compareTo(available) < 0) {
                                Log.i(TAG, "Update available from " + current + " to " + available);
                                showUpdateNotification(name, url);
                            } else
                                Log.i(TAG, "Up-to-date current version " + current);
                        }
                    }
                }
            } catch (JSONException ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }

        private class StartFailedException extends IllegalStateException {
            public StartFailedException(String msg) {
                super(msg);
            }
        }
    }

    private final class LogHandler extends Handler {
        public LogHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            try {
                if (powersaving && (msg.what == MSG_PACKET || msg.what == MSG_USAGE))
                    return;

                switch (msg.what) {
                    case MSG_PACKET:
                        log((Packet) msg.obj, msg.arg1, msg.arg2 > 0);
                        break;

                    case MSG_USAGE:
                        usage((Usage) msg.obj);
                        break;

                    default:
                        Log.e(TAG, "Unknown log message=" + msg.what);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }

        private void log(Packet packet, int connection, boolean interactive) {
            // Get settings
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            boolean log = prefs.getBoolean("log", false);
            boolean log_app = prefs.getBoolean("log_app", false);

            DatabaseHelper dh = DatabaseHelper.getInstance(ServiceSinkhole.this);

            // Get real name
            String dname = dh.getQName(packet.uid, packet.daddr);

            // Traffic log
            if (log)
                dh.insertLog(packet, dname, connection, interactive);

            // Application log
            if (log_app && packet.uid >= 0 && !(packet.uid == 0 && packet.protocol == 17 && packet.dport == 53)) {
                if (!(packet.protocol == 6 /* TCP */ || packet.protocol == 17 /* UDP */))
                    packet.dport = 0;
                if (dh.updateAccess(packet, dname, -1)) {
                    lock.readLock().lock();
                    if (!mapNotify.containsKey(packet.uid) || mapNotify.get(packet.uid))
                        showAccessNotification(packet.uid);
                    lock.readLock().unlock();
                }
            }
        }

        private void usage(Usage usage) {
            if (usage.Uid >= 0 && !(usage.Uid == 0 && usage.Protocol == 17 && usage.DPort == 53)) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                boolean filter = prefs.getBoolean("filter", false);
                boolean log_app = prefs.getBoolean("log_app", false);
                boolean track_usage = prefs.getBoolean("track_usage", false);
                if (filter && log_app && track_usage) {
                    DatabaseHelper dh = DatabaseHelper.getInstance(ServiceSinkhole.this);
                    String dname = dh.getQName(usage.Uid, usage.DAddr);
                    Log.i(TAG, "Usage account " + usage + " dname=" + dname);
                    dh.updateUsage(usage, dname);
                }
            }
        }
    }

    private final class StatsHandler extends Handler {
        private boolean stats = false;
        private long when;

        private long t = -1;
        private long tx = -1;
        private long rx = -1;

        private List<Long> gt = new ArrayList<>();
        private List<Float> gtx = new ArrayList<>();
        private List<Float> grx = new ArrayList<>();

        private HashMap<Integer, Long> mapUidBytes = new HashMap<>();

        public StatsHandler(Looper looper) {
            super(looper);
        }

        @Override
        public void handleMessage(Message msg) {
            try {
                switch (msg.what) {
                    case MSG_STATS_START:
                        startStats();
                        break;

                    case MSG_STATS_STOP:
                        stopStats();
                        break;

                    case MSG_STATS_UPDATE:
                        updateStats();
                        break;

                    default:
                        Log.e(TAG, "Unknown stats message=" + msg.what);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }

        private void startStats() {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
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
                mapUidBytes.clear();
                stats = true;
                updateStats();
            }
        }

        private void stopStats() {
            Log.i(TAG, "Stats stop");
            stats = false;
            this.removeMessages(MSG_STATS_UPDATE);
            if (state == State.stats) {
                Log.d(TAG, "Stop foreground state=" + state.toString());
                stopForeground(true);
                state = State.none;
            } else
                NotificationManagerCompat.from(ServiceSinkhole.this).cancel(NOTIFY_TRAFFIC);
        }

        private void updateStats() {
            RemoteViews remoteViews = new RemoteViews(getPackageName(), R.layout.traffic);
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
            long frequency = Long.parseLong(prefs.getString("stats_frequency", "1000"));
            long samples = Long.parseLong(prefs.getString("stats_samples", "90"));
            boolean filter = prefs.getBoolean("filter", false);
            boolean show_top = prefs.getBoolean("show_top", false);
            int loglevel = Integer.parseInt(prefs.getString("loglevel", Integer.toString(Log.WARN)));

            // Schedule next update
            this.sendEmptyMessageDelayed(MSG_STATS_UPDATE, frequency);

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
                if (ttx < 0)
                    ttx = 0;
                if (trx < 0)
                    trx = 0;
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
                if (mapUidBytes.size() == 0) {
                    for (ApplicationInfo ainfo : getPackageManager().getInstalledApplications(0))
                        if (ainfo.uid != Process.myUid())
                            mapUidBytes.put(ainfo.uid, TrafficStats.getUidTxBytes(ainfo.uid) + TrafficStats.getUidRxBytes(ainfo.uid));

                } else if (t > 0) {
                    TreeMap<Float, Integer> mapSpeedUid = new TreeMap<>(new Comparator<Float>() {
                        @Override
                        public int compare(Float value, Float other) {
                            return -value.compareTo(other);
                        }
                    });
                    float dt = (ct - t) / 1000f;
                    for (int uid : mapUidBytes.keySet()) {
                        long bytes = TrafficStats.getUidTxBytes(uid) + TrafficStats.getUidRxBytes(uid);
                        float speed = (bytes - mapUidBytes.get(uid)) / dt;
                        if (speed > 0) {
                            mapSpeedUid.put(speed, uid);
                            mapUidBytes.put(uid, bytes);
                        }
                    }

                    StringBuilder sb = new StringBuilder();
                    int i = 0;
                    for (float speed : mapSpeedUid.keySet()) {
                        if (i++ >= 3)
                            break;
                        if (speed < 1000 * 1000)
                            sb.append(getString(R.string.msg_kbsec, speed / 1000));
                        else
                            sb.append(getString(R.string.msg_mbsec, speed / 1000 / 1000));
                        sb.append(' ');
                        List<String> apps = Util.getApplicationNames(mapSpeedUid.get(speed), ServiceSinkhole.this);
                        sb.append(apps.size() > 0 ? apps.get(0) : "?");
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
            int height = Util.dips2pixels(96, ServiceSinkhole.this);
            int width = Util.dips2pixels(96 * 5, ServiceSinkhole.this);
            Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);

            // Create canvas
            Canvas canvas = new Canvas(bitmap);
            canvas.drawColor(Color.TRANSPARENT);

            // Determine max
            float max = 0;
            long xmax = 0;
            float ymax = 0;
            for (int i = 0; i < gt.size(); i++) {
                long t = gt.get(i);
                float tx = gtx.get(i);
                float rx = grx.get(i);
                if (t > xmax)
                    xmax = t;
                if (tx > max)
                    max = tx;
                if (rx > max)
                    max = rx;
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

            // Draw scale line
            paint.setStrokeWidth(Util.dips2pixels(1, ServiceSinkhole.this));
            paint.setColor(ContextCompat.getColor(ServiceSinkhole.this, R.color.colorGrayed));
            float y = height / 2;
            canvas.drawLine(0, y, width, y, paint);

            // Draw paths
            paint.setStrokeWidth(Util.dips2pixels(2, ServiceSinkhole.this));
            paint.setColor(ContextCompat.getColor(ServiceSinkhole.this, R.color.colorSend));
            canvas.drawPath(ptx, paint);
            paint.setColor(ContextCompat.getColor(ServiceSinkhole.this, R.color.colorReceive));
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

            if (max < 1000 * 1000)
                remoteViews.setTextViewText(R.id.tvMax, getString(R.string.msg_kbsec, max / 2 / 1000));
            else
                remoteViews.setTextViewText(R.id.tvMax, getString(R.string.msg_mbsec, max / 2 / 1000 / 1000));

            // Show session/file count
            if (filter && loglevel <= Log.WARN) {
                int[] count = jni_get_stats(jni_context);
                remoteViews.setTextViewText(R.id.tvSessions, count[0] + "/" + count[1] + "/" + count[2]);
                remoteViews.setTextViewText(R.id.tvFiles, count[3] + "/" + count[4]);
            } else {
                remoteViews.setTextViewText(R.id.tvSessions, "");
                remoteViews.setTextViewText(R.id.tvFiles, "");
            }

            // Show notification
            Intent main = new Intent(ServiceSinkhole.this, ActivityMain.class);
            PendingIntent pi = PendingIntent.getActivity(ServiceSinkhole.this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

            TypedValue tv = new TypedValue();
            getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
            NotificationCompat.Builder builder = new NotificationCompat.Builder(ServiceSinkhole.this, "notify");
            builder.setWhen(when)
                    .setSmallIcon(R.drawable.ic_equalizer_white_24dp)
                    .setContent(remoteViews)
                    .setContentIntent(pi)
                    .setColor(tv.data)
                    .setOngoing(true)
                    .setAutoCancel(false);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
                builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                        .setVisibility(NotificationCompat.VISIBILITY_PUBLIC);

            if (state == State.none || state == State.waiting) {
                if (state != State.none) {
                    Log.d(TAG, "Stop foreground state=" + state.toString());
                    stopForeground(true);
                }
                startForeground(NOTIFY_TRAFFIC, builder.build());
                state = State.stats;
                Log.d(TAG, "Start foreground state=" + state.toString());
            } else
                NotificationManagerCompat.from(ServiceSinkhole.this).notify(NOTIFY_TRAFFIC, builder.build());
        }
    }

    public static List<InetAddress> getDns(Context context) {
        List<InetAddress> listDns = new ArrayList<>();
        List<String> sysDns = Util.getDefaultDNS(context);

        // Get custom DNS servers
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean ip6 = prefs.getBoolean("ip6", true);
        String vpnDns1 = prefs.getString("dns", null);
        String vpnDns2 = prefs.getString("dns2", null);
        Log.i(TAG, "DNS system=" + TextUtils.join(",", sysDns) + " VPN1=" + vpnDns1 + " VPN2=" + vpnDns2);

        if (vpnDns1 != null)
            try {
                InetAddress dns = InetAddress.getByName(vpnDns1);
                if (!(dns.isLoopbackAddress() || dns.isAnyLocalAddress()) &&
                        (ip6 || dns instanceof Inet4Address))
                    listDns.add(dns);
            } catch (Throwable ignored) {
            }

        if (vpnDns2 != null)
            try {
                InetAddress dns = InetAddress.getByName(vpnDns2);
                if (!(dns.isLoopbackAddress() || dns.isAnyLocalAddress()) &&
                        (ip6 || dns instanceof Inet4Address))
                    listDns.add(dns);
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

        // Use system DNS servers only when no two custom DNS servers specified
        if (listDns.size() <= 1)
            for (String def_dns : sysDns)
                try {
                    InetAddress ddns = InetAddress.getByName(def_dns);
                    if (!listDns.contains(ddns) &&
                            !(ddns.isLoopbackAddress() || ddns.isAnyLocalAddress()) &&
                            (ip6 || ddns instanceof Inet4Address))
                        listDns.add(ddns);
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

        // Remove local DNS servers when not routing LAN
        boolean lan = prefs.getBoolean("lan", false);
        boolean use_hosts = prefs.getBoolean("filter", false) && prefs.getBoolean("use_hosts", false);
        if (lan && use_hosts) {
            List<InetAddress> listLocal = new ArrayList<>();
            try {
                Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
                if (nis != null)
                    while (nis.hasMoreElements()) {
                        NetworkInterface ni = nis.nextElement();
                        if (ni != null && ni.isUp() && !ni.isLoopback()) {
                            List<InterfaceAddress> ias = ni.getInterfaceAddresses();
                            if (ias != null)
                                for (InterfaceAddress ia : ias) {
                                    InetAddress hostAddress = ia.getAddress();
                                    BigInteger host = new BigInteger(1, hostAddress.getAddress());

                                    int prefix = ia.getNetworkPrefixLength();
                                    BigInteger mask = BigInteger.valueOf(-1).shiftLeft(hostAddress.getAddress().length * 8 - prefix);

                                    for (InetAddress dns : listDns)
                                        if (hostAddress.getAddress().length == dns.getAddress().length) {
                                            BigInteger ip = new BigInteger(1, dns.getAddress());

                                            if (host.and(mask).equals(ip.and(mask))) {
                                                Log.i(TAG, "Local DNS server host=" + hostAddress + "/" + prefix + " dns=" + dns);
                                                listLocal.add(dns);
                                            }
                                        }
                                }
                        }
                    }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

            List<InetAddress> listDns4 = new ArrayList<>();
            List<InetAddress> listDns6 = new ArrayList<>();
            try {
                listDns4.add(InetAddress.getByName("8.8.8.8"));
                listDns4.add(InetAddress.getByName("8.8.4.4"));
                if (ip6) {
                    listDns6.add(InetAddress.getByName("2001:4860:4860::8888"));
                    listDns6.add(InetAddress.getByName("2001:4860:4860::8844"));
                }

            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

            for (InetAddress dns : listLocal) {
                listDns.remove(dns);
                if (dns instanceof Inet4Address) {
                    if (listDns4.size() > 0) {
                        listDns.add(listDns4.get(0));
                        listDns4.remove(0);
                    }
                } else {
                    if (listDns6.size() > 0) {
                        listDns.add(listDns6.get(0));
                        listDns6.remove(0);
                    }
                }
            }
        }

        return listDns;
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private ParcelFileDescriptor startVPN(Builder builder) throws SecurityException {
        try {
            return builder.establish();
        } catch (SecurityException ex) {
            throw ex;
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            return null;
        }
    }

    private Builder getBuilder(List<Rule> listAllowed, List<Rule> listRule) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean subnet = prefs.getBoolean("subnet", false);
        boolean tethering = prefs.getBoolean("tethering", false);
        boolean lan = prefs.getBoolean("lan", false);
        boolean ip6 = prefs.getBoolean("ip6", true);
        boolean filter = prefs.getBoolean("filter", false);
        boolean system = prefs.getBoolean("manage_system", false);

        // Build VPN service
        Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name));

        // VPN address
        String vpn4 = prefs.getString("vpn4", "10.1.10.1");
        Log.i(TAG, "vpn4=" + vpn4);
        builder.addAddress(vpn4, 32);
        if (ip6) {
            String vpn6 = prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1");
            Log.i(TAG, "vpn6=" + vpn6);
            builder.addAddress(vpn6, 128);
        }

        // DNS address
        if (filter)
            for (InetAddress dns : getDns(ServiceSinkhole.this)) {
                if (ip6 || dns instanceof Inet4Address) {
                    Log.i(TAG, "dns=" + dns);
                    builder.addDnsServer(dns);
                }
            }

        // Subnet routing
        if (subnet) {
            // Exclude IP ranges
            List<IPUtil.CIDR> listExclude = new ArrayList<>();
            listExclude.add(new IPUtil.CIDR("127.0.0.0", 8)); // localhost

            if (tethering) {
                // USB tethering 192.168.42.x
                // Wi-Fi tethering 192.168.43.x
                listExclude.add(new IPUtil.CIDR("192.168.42.0", 23));
                // Wi-Fi direct 192.168.49.x
                listExclude.add(new IPUtil.CIDR("192.168.49.0", 24));
            }

            if (lan) {
                try {
                    Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
                    while (nis.hasMoreElements()) {
                        NetworkInterface ni = nis.nextElement();
                        if (ni != null && ni.isUp() && !ni.isLoopback() &&
                                ni.getName() != null && !ni.getName().startsWith("tun"))
                            for (InterfaceAddress ia : ni.getInterfaceAddresses())
                                if (ia.getAddress() instanceof Inet4Address) {
                                    IPUtil.CIDR local = new IPUtil.CIDR(ia.getAddress(), ia.getNetworkPrefixLength());
                                    Log.i(TAG, "Excluding " + ni.getName() + " " + local);
                                    listExclude.add(local);
                                }
                    }
                } catch (SocketException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
            }

            // https://en.wikipedia.org/wiki/Mobile_country_code
            Configuration config = getResources().getConfiguration();

            // T-Mobile Wi-Fi calling
            if (config.mcc == 310 && (config.mnc == 160 ||
                    config.mnc == 200 ||
                    config.mnc == 210 ||
                    config.mnc == 220 ||
                    config.mnc == 230 ||
                    config.mnc == 240 ||
                    config.mnc == 250 ||
                    config.mnc == 260 ||
                    config.mnc == 270 ||
                    config.mnc == 310 ||
                    config.mnc == 490 ||
                    config.mnc == 660 ||
                    config.mnc == 800)) {
                listExclude.add(new IPUtil.CIDR("66.94.2.0", 24));
                listExclude.add(new IPUtil.CIDR("66.94.6.0", 23));
                listExclude.add(new IPUtil.CIDR("66.94.8.0", 22));
                listExclude.add(new IPUtil.CIDR("208.54.0.0", 16));
            }

            // Verizon wireless calling
            if ((config.mcc == 310 &&
                    (config.mnc == 4 ||
                            config.mnc == 5 ||
                            config.mnc == 6 ||
                            config.mnc == 10 ||
                            config.mnc == 12 ||
                            config.mnc == 13 ||
                            config.mnc == 350 ||
                            config.mnc == 590 ||
                            config.mnc == 820 ||
                            config.mnc == 890 ||
                            config.mnc == 910)) ||
                    (config.mcc == 311 && (config.mnc == 12 ||
                            config.mnc == 110 ||
                            (config.mnc >= 270 && config.mnc <= 289) ||
                            config.mnc == 390 ||
                            (config.mnc >= 480 && config.mnc <= 489) ||
                            config.mnc == 590)) ||
                    (config.mcc == 312 && (config.mnc == 770))) {
                listExclude.add(new IPUtil.CIDR("66.174.0.0", 16)); // 66.174.0.0 - 66.174.255.255
                listExclude.add(new IPUtil.CIDR("66.82.0.0", 15)); // 69.82.0.0 - 69.83.255.255
                listExclude.add(new IPUtil.CIDR("69.96.0.0", 13)); // 69.96.0.0 - 69.103.255.255
                listExclude.add(new IPUtil.CIDR("70.192.0.0", 11)); // 70.192.0.0 - 70.223.255.255
                listExclude.add(new IPUtil.CIDR("97.128.0.0", 9)); // 97.128.0.0 - 97.255.255.255
                listExclude.add(new IPUtil.CIDR("174.192.0.0", 9)); // 174.192.0.0 - 174.255.255.255
                listExclude.add(new IPUtil.CIDR("72.96.0.0", 9)); // 72.96.0.0 - 72.127.255.255
                listExclude.add(new IPUtil.CIDR("75.192.0.0", 9)); // 75.192.0.0 - 75.255.255.255
                listExclude.add(new IPUtil.CIDR("97.0.0.0", 10)); // 97.0.0.0 - 97.63.255.255
            }

            // Broadcast
            listExclude.add(new IPUtil.CIDR("224.0.0.0", 3));

            Collections.sort(listExclude);

            try {
                InetAddress start = InetAddress.getByName("0.0.0.0");
                for (IPUtil.CIDR exclude : listExclude) {
                    Log.i(TAG, "Exclude " + exclude.getStart().getHostAddress() + "..." + exclude.getEnd().getHostAddress());
                    for (IPUtil.CIDR include : IPUtil.toCIDR(start, IPUtil.minus1(exclude.getStart())))
                        try {
                            builder.addRoute(include.address, include.prefix);
                        } catch (Throwable ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
                    start = IPUtil.plus1(exclude.getEnd());
                }
                String end = (lan ? "255.255.255.254" : "255.255.255.255");
                for (IPUtil.CIDR include : IPUtil.toCIDR("224.0.0.0", end))
                    try {
                        builder.addRoute(include.address, include.prefix);
                    } catch (Throwable ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
            } catch (UnknownHostException ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        } else
            builder.addRoute("0.0.0.0", 0);

        Log.i(TAG, "IPv6=" + ip6);
        if (ip6)
            builder.addRoute("2000::", 3); // unicast

        // MTU
        int mtu = jni_get_mtu();
        Log.i(TAG, "MTU=" + mtu);
        builder.setMtu(mtu);

        // Add list of allowed applications
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
                builder.addDisallowedApplication(getPackageName());
            } catch (PackageManager.NameNotFoundException ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
            if (last_connected && !filter)
                for (Rule rule : listAllowed)
                    try {
                        builder.addDisallowedApplication(rule.packageName);
                    } catch (PackageManager.NameNotFoundException ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
            else if (filter)
                for (Rule rule : listRule)
                    if (!rule.apply || (!system && rule.system))
                        try {
                            Log.i(TAG, "Not routing " + rule.packageName);
                            builder.addDisallowedApplication(rule.packageName);
                        } catch (PackageManager.NameNotFoundException ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
        }

        // Build configure intent
        Intent configure = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, configure, PendingIntent.FLAG_UPDATE_CURRENT);
        builder.setConfigureIntent(pi);

        return builder;
    }

    private void startNative(final ParcelFileDescriptor vpn, List<Rule> listAllowed, List<Rule> listRule) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
        boolean log = prefs.getBoolean("log", false);
        boolean log_app = prefs.getBoolean("log_app", false);
        boolean filter = prefs.getBoolean("filter", false);

        Log.i(TAG, "Start native log=" + log + "/" + log_app + " filter=" + filter);

        // Prepare rules
        if (filter) {
            prepareUidAllowed(listAllowed, listRule);
            prepareHostsBlocked();
            prepareUidIPFilters(null);
            prepareForwarding();
        } else {
            lock.writeLock().lock();
            mapUidAllowed.clear();
            mapUidKnown.clear();
            mapHostsBlocked.clear();
            mapUidIPFilters.clear();
            mapForward.clear();
            lock.writeLock().unlock();
        }

        if (log_app)
            prepareNotify(listRule);
        else {
            lock.writeLock().lock();
            mapNotify.clear();
            lock.writeLock().unlock();
        }

        if (log || log_app || filter) {
            int prio = Integer.parseInt(prefs.getString("loglevel", Integer.toString(Log.WARN)));
            final int rcode = Integer.parseInt(prefs.getString("rcode", "3"));
            if (prefs.getBoolean("socks5_enabled", false))
                jni_socks5(
                        prefs.getString("socks5_addr", ""),
                        Integer.parseInt(prefs.getString("socks5_port", "0")),
                        prefs.getString("socks5_username", ""),
                        prefs.getString("socks5_password", ""));
            else
                jni_socks5("", 0, "", "");

            if (tunnelThread == null) {
                Log.i(TAG, "Starting tunnel thread");
                jni_start(jni_context, prio);

                tunnelThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Log.i(TAG, "Running tunnel");
                        jni_run(jni_context, vpn.getFd(), mapForward.containsKey(53), rcode);
                        Log.i(TAG, "Tunnel exited");
                        tunnelThread = null;
                    }
                });
                //tunnelThread.setPriority(Thread.MAX_PRIORITY);
                tunnelThread.start();

                Log.i(TAG, "Started tunnel thread");
            }
        }
    }

    private void stopNative(ParcelFileDescriptor vpn, boolean clear) {
        Log.i(TAG, "Stop native clear=" + clear);

        if (tunnelThread != null) {
            Log.i(TAG, "Stopping tunnel thread");

            jni_stop(jni_context);

            Thread thread = tunnelThread;
            while (thread != null)
                try {
                    thread.join();
                    break;
                } catch (InterruptedException ignored) {
                }
            tunnelThread = null;

            if (clear)
                jni_clear(jni_context);

            Log.i(TAG, "Stopped tunnel thread");
        }
    }

    private void unprepare() {
        lock.writeLock().lock();
        mapUidAllowed.clear();
        mapUidKnown.clear();
        mapHostsBlocked.clear();
        mapUidIPFilters.clear();
        mapForward.clear();
        mapNotify.clear();
        lock.writeLock().unlock();
    }

    private void prepareUidAllowed(List<Rule> listAllowed, List<Rule> listRule) {
        lock.writeLock().lock();

        mapUidAllowed.clear();
        for (Rule rule : listAllowed)
            mapUidAllowed.put(rule.uid, true);

        mapUidKnown.clear();
        for (Rule rule : listRule)
            mapUidKnown.put(rule.uid, rule.uid);

        lock.writeLock().unlock();
    }

    private void prepareHostsBlocked() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
        boolean use_hosts = prefs.getBoolean("filter", false) && prefs.getBoolean("use_hosts", false);
        File hosts = new File(getFilesDir(), "hosts.txt");
        if (!use_hosts || !hosts.exists() || !hosts.canRead()) {
            Log.i(TAG, "Hosts file use=" + use_hosts + " exists=" + hosts.exists());
            lock.writeLock().lock();
            mapHostsBlocked.clear();
            lock.writeLock().unlock();
            return;
        }

        boolean changed = (hosts.lastModified() != last_hosts_modified);
        if (!changed && mapHostsBlocked.size() > 0) {
            Log.i(TAG, "Hosts file unchanged");
            return;
        }
        last_hosts_modified = hosts.lastModified();

        lock.writeLock().lock();

        mapHostsBlocked.clear();

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
            mapHostsBlocked.put("test.netguard.me", true);
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

        lock.writeLock().unlock();
    }

    private void prepareUidIPFilters(String dname) {
        SharedPreferences lockdown = getSharedPreferences("lockdown", Context.MODE_PRIVATE);

        lock.writeLock().lock();

        if (dname == null) {
            mapUidIPFilters.clear();
            if (!IAB.isPurchased(ActivityPro.SKU_FILTER, ServiceSinkhole.this)) {
                lock.writeLock().unlock();
                return;
            }
        }

        Cursor cursor = DatabaseHelper.getInstance(ServiceSinkhole.this).getAccessDns(dname);
        int colUid = cursor.getColumnIndex("uid");
        int colVersion = cursor.getColumnIndex("version");
        int colProtocol = cursor.getColumnIndex("protocol");
        int colDAddr = cursor.getColumnIndex("daddr");
        int colResource = cursor.getColumnIndex("resource");
        int colDPort = cursor.getColumnIndex("dport");
        int colBlock = cursor.getColumnIndex("block");
        int colTime = cursor.getColumnIndex("time");
        int colTTL = cursor.getColumnIndex("ttl");
        while (cursor.moveToNext()) {
            int uid = cursor.getInt(colUid);
            int version = cursor.getInt(colVersion);
            int protocol = cursor.getInt(colProtocol);
            String daddr = cursor.getString(colDAddr);
            String dresource = cursor.getString(colResource);
            int dport = cursor.getInt(colDPort);
            boolean block = (cursor.getInt(colBlock) > 0);
            long time = cursor.getLong(colTime);
            long ttl = cursor.getLong(colTTL);

            if (isLockedDown(last_metered)) {
                String[] pkg = getPackageManager().getPackagesForUid(uid);
                if (pkg != null && pkg.length > 0) {
                    if (!lockdown.getBoolean(pkg[0], false))
                        continue;
                }
            }

            // long is 64 bits
            // 0..15 uid
            // 16..31 dport
            // 32..39 protocol
            // 40..43 version
            if (!(protocol == 6 /* TCP */ || protocol == 17 /* UDP */))
                dport = 0;
            long key = (version << 40) | (protocol << 32) | (dport << 16) | uid;

            synchronized (mapUidIPFilters) {
                if (!mapUidIPFilters.containsKey(key))
                    mapUidIPFilters.put(key, new HashMap());

                try {
                    if (dname != null)
                        Log.i(TAG, "Set filter uid=" + uid + " " + daddr + " " + dresource + "/" + dport + "=" + block);
                    String name = (dresource == null ? daddr : dresource);
                    if (Util.isNumericAddress(name)) {
                        InetAddress iname = InetAddress.getByName(name);
                        boolean exists = mapUidIPFilters.get(key).containsKey(iname);
                        if (!exists || !mapUidIPFilters.get(key).get(iname).isBlocked()) {
                            IPRule rule = new IPRule(block, time + ttl);
                            mapUidIPFilters.get(key).put(iname, rule);
                            if (exists)
                                Log.w(TAG, "Address conflict uid=" + uid + " " + daddr + " " + dresource + "/" + dport);
                        } else if (exists) {
                            mapUidIPFilters.get(key).get(iname).updateExpires(time + ttl);
                            Log.w(TAG, "Address updated uid=" + uid + " " + daddr + " " + dresource + "/" + dport);
                        }
                    } else
                        Log.w(TAG, "Address not numeric " + name);
                } catch (UnknownHostException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
            }
        }
        cursor.close();

        lock.writeLock().unlock();
    }

    private void prepareForwarding() {
        lock.writeLock().lock();
        mapForward.clear();

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        if (prefs.getBoolean("filter", false)) {
            Cursor cursor = DatabaseHelper.getInstance(ServiceSinkhole.this).getForwarding();
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
        }
        lock.writeLock().unlock();
    }

    private void prepareNotify(List<Rule> listRule) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean notify = prefs.getBoolean("notify_access", false);
        boolean system = prefs.getBoolean("manage_system", false);

        lock.writeLock().lock();
        mapNotify.clear();
        for (Rule rule : listRule)
            mapNotify.put(rule.uid, notify && rule.notify && (system || !rule.system));
        lock.writeLock().unlock();
    }

    private boolean isLockedDown(boolean metered) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
        boolean lockdown = prefs.getBoolean("lockdown", false);
        boolean lockdown_wifi = prefs.getBoolean("lockdown_wifi", true);
        boolean lockdown_other = prefs.getBoolean("lockdown_other", true);
        if (metered ? !lockdown_other : !lockdown_wifi)
            lockdown = false;

        return lockdown;
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
        boolean roaming = Util.isRoaming(ServiceSinkhole.this);
        boolean national = prefs.getBoolean("national_roaming", false);
        boolean eu = prefs.getBoolean("eu_roaming", false);
        boolean tethering = prefs.getBoolean("tethering", false);
        boolean filter = prefs.getBoolean("filter", false);

        // Update connected state
        last_connected = Util.isConnected(ServiceSinkhole.this);

        boolean org_metered = metered;
        boolean org_roaming = roaming;

        // Update metered state
        if (wifi && !useMetered)
            metered = false;
        if (wifi && ssidHomes.size() > 0 &&
                !(ssidHomes.contains(ssidNetwork) || ssidHomes.contains('"' + ssidNetwork + '"'))) {
            metered = true;
            Log.i(TAG, "!@home");
        }
        if (unmetered_2g && "2G".equals(generation))
            metered = false;
        if (unmetered_3g && "3G".equals(generation))
            metered = false;
        if (unmetered_4g && "4G".equals(generation))
            metered = false;
        last_metered = metered;

        boolean lockdown = isLockedDown(last_metered);

        // Update roaming state
        if (roaming && eu)
            roaming = !Util.isEU(this);
        if (roaming && national)
            roaming = !Util.isNational(this);

        Log.i(TAG, "Get allowed" +
                " connected=" + last_connected +
                " wifi=" + wifi +
                " home=" + TextUtils.join(",", ssidHomes) +
                " network=" + ssidNetwork +
                " metered=" + metered + "/" + org_metered +
                " generation=" + generation +
                " roaming=" + roaming + "/" + org_roaming +
                " interactive=" + last_interactive +
                " tethering=" + tethering +
                " filter=" + filter +
                " lockdown=" + lockdown);

        if (last_connected)
            for (Rule rule : listRule) {
                boolean blocked = (metered ? rule.other_blocked : rule.wifi_blocked);
                boolean screen = (metered ? rule.screen_other : rule.screen_wifi);
                if ((!blocked || (screen && last_interactive)) &&
                        (!metered || !(rule.roaming && roaming)) &&
                        (!lockdown || rule.lockdown))
                    listAllowed.add(rule);
            }

        Log.i(TAG, "Allowed " + listAllowed.size() + " of " + listRule.size());
        return listAllowed;
    }

    private void stopVPN(ParcelFileDescriptor pfd) {
        Log.i(TAG, "Stopping");
        try {
            pfd.close();
        } catch (IOException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
    }

    // Called from native code
    private void nativeExit(String reason) {
        Log.w(TAG, "Native exit reason=" + reason);
        if (reason != null) {
            showErrorNotification(reason);

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean("enabled", false).apply();
            WidgetMain.updateWidgets(this);
        }
    }

    // Called from native code
    private void nativeError(int error, String message) {
        Log.w(TAG, "Native error " + error + ": " + message);
        showErrorNotification(message);
    }

    // Called from native code
    private void logPacket(Packet packet) {
        Message msg = logHandler.obtainMessage();
        msg.obj = packet;
        msg.what = MSG_PACKET;
        msg.arg1 = (last_connected ? (last_metered ? 2 : 1) : 0);
        msg.arg2 = (last_interactive ? 1 : 0);
        logHandler.sendMessage(msg);
    }

    // Called from native code
    private void dnsResolved(ResourceRecord rr) {
        if (DatabaseHelper.getInstance(ServiceSinkhole.this).insertDns(rr)) {
            Log.i(TAG, "New IP " + rr);
            prepareUidIPFilters(rr.QName);
        }
    }

    // Called from native code
    private boolean isDomainBlocked(String name) {
        lock.readLock().lock();
        boolean blocked = (mapHostsBlocked.containsKey(name) && mapHostsBlocked.get(name));
        lock.readLock().unlock();
        return blocked;
    }

    private boolean isSupported(int protocol) {
        return (protocol == 1 /* ICMPv4 */ ||
                protocol == 59 /* ICMPv6 */ ||
                protocol == 6 /* TCP */ ||
                protocol == 17 /* UDP */);
    }

    // Called from native code
    private Allowed isAddressAllowed(Packet packet) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        lock.readLock().lock();

        packet.allowed = false;
        if (prefs.getBoolean("filter", false)) {
            // https://android.googlesource.com/platform/system/core/+/master/include/private/android_filesystem_config.h
            if (packet.uid < 2000 &&
                    !last_connected && isSupported(packet.protocol)) {
                // Allow system applications in disconnected state
                packet.allowed = true;
                Log.w(TAG, "Allowing disconnected system " + packet);

            } else if (packet.uid < 2000 &&
                    !mapUidKnown.containsKey(packet.uid) && isSupported(packet.protocol)) {
                // Allow unknown system traffic
                packet.allowed = true;
                Log.w(TAG, "Allowing unknown system " + packet);
            } else if (packet.uid == Process.myUid()) {
                // Allow self
                packet.allowed = true;
                Log.w(TAG, "Allowing self " + packet);
            } else {
                boolean filtered = false;
                // Only TCP (6) and UDP (17) have port numbers
                int dport = (packet.protocol == 6 || packet.protocol == 17 ? packet.dport : 0);
                long key = (packet.version << 40) | (packet.protocol << 32) | (dport << 16) | packet.uid;

                if (mapUidIPFilters.containsKey(key))
                    try {
                        InetAddress iaddr = InetAddress.getByName(packet.daddr);
                        Map<InetAddress, IPRule> map = mapUidIPFilters.get(key);
                        if (map != null && map.containsKey(iaddr)) {
                            IPRule rule = map.get(iaddr);
                            if (rule.isExpired())
                                Log.i(TAG, "DNS expired " + packet);
                            else {
                                filtered = true;
                                packet.allowed = !rule.isBlocked();
                                Log.i(TAG, "Filtering " + packet);
                            }
                        }
                    } catch (UnknownHostException ex) {
                        Log.w(TAG, "Allowed " + ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }

                if (!filtered)
                    if (mapUidAllowed.containsKey(packet.uid))
                        packet.allowed = mapUidAllowed.get(packet.uid);
                    else
                        Log.w(TAG, "No rules for " + packet);
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
                    packet.data = "> " + fwd.raddr + "/" + fwd.rport;
                }
            } else
                allowed = new Allowed();
        }

        lock.readLock().unlock();

        if (prefs.getBoolean("log", false) || prefs.getBoolean("log_app", false))
            if (packet.protocol != 6 /* TCP */ || !"".equals(packet.flags))
                if (packet.uid != Process.myUid())
                    logPacket(packet);

        return allowed;
    }

    // Called from native code
    private void accountUsage(Usage usage) {
        Message msg = logHandler.obtainMessage();
        msg.obj = usage;
        msg.what = MSG_USAGE;
        logHandler.sendMessage(msg);
    }

    private BroadcastReceiver interactiveStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(final Context context, final Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            executor.submit(new Runnable() {
                @Override
                public void run() {
                    SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                    int delay;
                    try {
                        delay = Integer.parseInt(prefs.getString("screen_delay", "0"));
                    } catch (NumberFormatException ignored) {
                        delay = 0;
                    }
                    boolean interactive = Intent.ACTION_SCREEN_ON.equals(intent.getAction());

                    AlarmManager am = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
                    Intent i = new Intent(ACTION_SCREEN_OFF_DELAYED);
                    i.setPackage(context.getPackageName());
                    PendingIntent pi = PendingIntent.getBroadcast(context, 0, i, PendingIntent.FLAG_UPDATE_CURRENT);
                    am.cancel(pi);

                    if (interactive || delay == 0) {
                        last_interactive = interactive;
                        reload("interactive state changed", ServiceSinkhole.this, true);
                    } else {
                        if (ACTION_SCREEN_OFF_DELAYED.equals(intent.getAction())) {
                            last_interactive = interactive;
                            reload("interactive state changed", ServiceSinkhole.this, true);
                        } else {
                            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M)
                                am.set(AlarmManager.RTC_WAKEUP, new Date().getTime() + delay * 60 * 1000L, pi);
                            else
                                am.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, new Date().getTime() + delay * 60 * 1000L, pi);
                        }
                    }

                    // Start/stop stats
                    statsHandler.sendEmptyMessage(
                            Util.isInteractive(ServiceSinkhole.this) && !powersaving ? MSG_STATS_START : MSG_STATS_STOP);
                }
            });
        }
    };

    private BroadcastReceiver powerSaveReceiver = new BroadcastReceiver() {
        @Override
        @TargetApi(Build.VERSION_CODES.LOLLIPOP)
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            powersaving = pm.isPowerSaveMode();
            Log.i(TAG, "Power saving=" + powersaving);

            statsHandler.sendEmptyMessage(
                    Util.isInteractive(ServiceSinkhole.this) && !powersaving ? MSG_STATS_START : MSG_STATS_STOP);
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
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                if (prefs.getBoolean("enabled", false)) {
                    // Allow service of background user to stop
                    try {
                        Thread.sleep(3000);
                    } catch (InterruptedException ignored) {
                    }

                    start("foreground", ServiceSinkhole.this);
                }
            } else
                stop("background", ServiceSinkhole.this, false);
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
                reload("idle state changed", ServiceSinkhole.this, false);
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
            reload("connectivity changed", ServiceSinkhole.this, false);
        }
    };

    ConnectivityManager.NetworkCallback networkMonitorCallback = new ConnectivityManager.NetworkCallback() {
        private String TAG = "NetGuard.Monitor";

        private Map<Network, Long> validated = new HashMap<>();

        // https://android.googlesource.com/platform/frameworks/base/+/master/services/core/java/com/android/server/connectivity/NetworkMonitor.java

        @Override
        public void onAvailable(Network network) {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo ni = cm.getNetworkInfo(network);
            NetworkCapabilities capabilities = cm.getNetworkCapabilities(network);
            Log.i(TAG, "Available network " + network + " " + ni);
            Log.i(TAG, "Capabilities=" + capabilities);
            checkConnectivity(network, ni, capabilities);
        }

        @Override
        public void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo ni = cm.getNetworkInfo(network);
            Log.i(TAG, "New capabilities network " + network + " " + ni);
            Log.i(TAG, "Capabilities=" + capabilities);
            checkConnectivity(network, ni, capabilities);
        }

        @Override
        public void onLosing(Network network, int maxMsToLive) {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo ni = cm.getNetworkInfo(network);
            Log.i(TAG, "Losing network " + network + " within " + maxMsToLive + " ms " + ni);
        }

        @Override
        public void onLost(Network network) {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkInfo ni = cm.getNetworkInfo(network);
            Log.i(TAG, "Lost network " + network + " " + ni);

            synchronized (validated) {
                validated.remove(network);
            }
        }

        @Override
        public void onUnavailable() {
            Log.i(TAG, "No networks available");
        }

        private void checkConnectivity(Network network, NetworkInfo ni, NetworkCapabilities capabilities) {
            if (ni != null && capabilities != null &&
                    ni.getDetailedState() != NetworkInfo.DetailedState.SUSPENDED &&
                    ni.getDetailedState() != NetworkInfo.DetailedState.BLOCKED &&
                    ni.getDetailedState() != NetworkInfo.DetailedState.DISCONNECTED &&
                    capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {

                synchronized (validated) {
                    if (validated.containsKey(network) &&
                            validated.get(network) + 20 * 1000 > new Date().getTime()) {
                        Log.i(TAG, "Already validated " + network + " " + ni);
                        return;
                    }
                }

                Log.i(TAG, "Validating " + network + " " + ni);

                Socket socket = null;
                try {
                    socket = network.getSocketFactory().createSocket();
                    socket.connect(new InetSocketAddress("www.google.com", 443), 10000);
                    Log.i(TAG, "Validated " + network + " " + ni);
                    synchronized (validated) {
                        validated.put(network, new Date().getTime());
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                        cm.reportNetworkConnectivity(network, true);
                        Log.i(TAG, "Reported " + network + " " + ni);
                    }
                } catch (IOException ex) {
                    Log.e(TAG, ex.toString());
                    Log.i(TAG, "No connectivity " + network + " " + ni);
                } finally {
                    if (socket != null)
                        try {
                            socket.close();
                        } catch (IOException ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
                }
            }
        }
    };

    private PhoneStateListener phoneStateListener = new PhoneStateListener() {
        private String last_generation = null;

        @Override
        public void onDataConnectionStateChanged(int state, int networkType) {
            if (state == TelephonyManager.DATA_CONNECTED) {
                String current_generation = Util.getNetworkGeneration(ServiceSinkhole.this);
                Log.i(TAG, "Data connected generation=" + current_generation);

                if (last_generation == null || !last_generation.equals(current_generation)) {
                    Log.i(TAG, "New network generation=" + current_generation);
                    last_generation = current_generation;

                    SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                    if (prefs.getBoolean("unmetered_2g", false) ||
                            prefs.getBoolean("unmetered_3g", false) ||
                            prefs.getBoolean("unmetered_4g", false))
                        reload("data connection state changed", ServiceSinkhole.this, false);
                }
            }
        }
    };

    private BroadcastReceiver packageChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(intent);

            try {
                if (Intent.ACTION_PACKAGE_ADDED.equals(intent.getAction())) {
                    // Application added
                    Rule.clearCache(context);

                    if (!intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
                        // Show notification
                        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
                        if (IAB.isPurchased(ActivityPro.SKU_NOTIFY, context) && prefs.getBoolean("install", true)) {
                            int uid = intent.getIntExtra(Intent.EXTRA_UID, -1);
                            notifyNewApplication(uid);
                        }
                    }

                    reload("package added", context, false);

                } else if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())) {
                    // Application removed
                    Rule.clearCache(context);

                    if (intent.getBooleanExtra(Intent.EXTRA_DATA_REMOVED, false)) {
                        // Remove settings
                        String packageName = intent.getData().getSchemeSpecificPart();
                        Log.i(TAG, "Deleting settings package=" + packageName);
                        context.getSharedPreferences("wifi", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("other", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("screen_other", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("roaming", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("lockdown", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("apply", Context.MODE_PRIVATE).edit().remove(packageName).apply();
                        context.getSharedPreferences("notify", Context.MODE_PRIVATE).edit().remove(packageName).apply();

                        int uid = intent.getIntExtra(Intent.EXTRA_UID, 0);
                        if (uid > 0) {
                            DatabaseHelper dh = DatabaseHelper.getInstance(context);
                            dh.clearLog(uid);
                            dh.clearAccess(uid, false);

                            NotificationManagerCompat.from(context).cancel(uid); // installed notification
                            NotificationManagerCompat.from(context).cancel(uid + 10000); // access notification
                        }
                    }

                    reload("package deleted", context, false);
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }
        }
    };

    public void notifyNewApplication(int uid) {
        if (uid < 0)
            return;

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        try {
            // Get application name
            String name = TextUtils.join(", ", Util.getApplicationNames(uid, this));

            // Get application info
            PackageManager pm = getPackageManager();
            String[] packages = pm.getPackagesForUid(uid);
            if (packages == null || packages.length < 1)
                throw new PackageManager.NameNotFoundException(Integer.toString(uid));
            boolean internet = Util.hasInternet(uid, this);

            // Build notification
            Intent main = new Intent(this, ActivityMain.class);
            main.putExtra(ActivityMain.EXTRA_REFRESH, true);
            main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
            PendingIntent pi = PendingIntent.getActivity(this, uid, main, PendingIntent.FLAG_UPDATE_CURRENT);

            TypedValue tv = new TypedValue();
            getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
            NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
            builder.setSmallIcon(R.drawable.ic_security_white_24dp)
                    .setContentIntent(pi)
                    .setColor(tv.data)
                    .setAutoCancel(true);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
                builder.setContentTitle(name)
                        .setContentText(getString(R.string.msg_installed_n));
            else
                builder.setContentTitle(getString(R.string.app_name))
                        .setContentText(getString(R.string.msg_installed, name));

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
                builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                        .setVisibility(NotificationCompat.VISIBILITY_SECRET);

            // Get defaults
            SharedPreferences prefs_wifi = getSharedPreferences("wifi", Context.MODE_PRIVATE);
            SharedPreferences prefs_other = getSharedPreferences("other", Context.MODE_PRIVATE);
            boolean wifi = prefs_wifi.getBoolean(packages[0], prefs.getBoolean("whitelist_wifi", true));
            boolean other = prefs_other.getBoolean(packages[0], prefs.getBoolean("whitelist_other", true));

            // Build Wi-Fi action
            Intent riWifi = new Intent(this, ServiceSinkhole.class);
            riWifi.putExtra(ServiceSinkhole.EXTRA_COMMAND, ServiceSinkhole.Command.set);
            riWifi.putExtra(ServiceSinkhole.EXTRA_NETWORK, "wifi");
            riWifi.putExtra(ServiceSinkhole.EXTRA_UID, uid);
            riWifi.putExtra(ServiceSinkhole.EXTRA_PACKAGE, packages[0]);
            riWifi.putExtra(ServiceSinkhole.EXTRA_BLOCKED, !wifi);

            PendingIntent piWifi = PendingIntent.getService(this, uid, riWifi, PendingIntent.FLAG_UPDATE_CURRENT);
            NotificationCompat.Action wAction = new NotificationCompat.Action.Builder(
                    wifi ? R.drawable.wifi_on : R.drawable.wifi_off,
                    getString(wifi ? R.string.title_allow_wifi : R.string.title_block_wifi),
                    piWifi
            ).build();
            builder.addAction(wAction);

            // Build mobile action
            Intent riOther = new Intent(this, ServiceSinkhole.class);
            riOther.putExtra(ServiceSinkhole.EXTRA_COMMAND, ServiceSinkhole.Command.set);
            riOther.putExtra(ServiceSinkhole.EXTRA_NETWORK, "other");
            riOther.putExtra(ServiceSinkhole.EXTRA_UID, uid);
            riOther.putExtra(ServiceSinkhole.EXTRA_PACKAGE, packages[0]);
            riOther.putExtra(ServiceSinkhole.EXTRA_BLOCKED, !other);
            PendingIntent piOther = PendingIntent.getService(this, uid + 10000, riOther, PendingIntent.FLAG_UPDATE_CURRENT);
            NotificationCompat.Action oAction = new NotificationCompat.Action.Builder(
                    other ? R.drawable.other_on : R.drawable.other_off,
                    getString(other ? R.string.title_allow_other : R.string.title_block_other),
                    piOther
            ).build();
            builder.addAction(oAction);

            // Show notification
            if (internet)
                NotificationManagerCompat.from(this).notify(uid, builder.build());
            else {
                NotificationCompat.BigTextStyle expanded = new NotificationCompat.BigTextStyle(builder);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
                    expanded.bigText(getString(R.string.msg_installed_n));
                else
                    expanded.bigText(getString(R.string.msg_installed, name));
                expanded.setSummaryText(getString(R.string.title_internet));
                NotificationManagerCompat.from(this).notify(uid, expanded.build());
            }

        } catch (PackageManager.NameNotFoundException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
    }

    @Override
    public void onCreate() {
        Log.i(TAG, "Create version=" + Util.getSelfVersionName(this) + "/" + Util.getSelfVersionCode(this));

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Native init
        jni_context = jni_init(Build.VERSION.SDK_INT);
        boolean pcap = prefs.getBoolean("pcap", false);
        setPcap(pcap, this);

        prefs.registerOnSharedPreferenceChangeListener(this);

        Util.setTheme(this);
        super.onCreate();

        HandlerThread commandThread = new HandlerThread(getString(R.string.app_name) + " command", Process.THREAD_PRIORITY_FOREGROUND);
        HandlerThread logThread = new HandlerThread(getString(R.string.app_name) + " log", Process.THREAD_PRIORITY_BACKGROUND);
        HandlerThread statsThread = new HandlerThread(getString(R.string.app_name) + " stats", Process.THREAD_PRIORITY_BACKGROUND);
        commandThread.start();
        logThread.start();
        statsThread.start();

        commandLooper = commandThread.getLooper();
        logLooper = logThread.getLooper();
        statsLooper = statsThread.getLooper();

        commandHandler = new CommandHandler(commandLooper);
        logHandler = new LogHandler(logLooper);
        statsHandler = new StatsHandler(statsLooper);

        // Listen for power save mode
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && !Util.isPlayStoreInstall(this)) {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            powersaving = pm.isPowerSaveMode();
            IntentFilter ifPower = new IntentFilter();
            ifPower.addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED);
            registerReceiver(powerSaveReceiver, ifPower);
            registeredPowerSave = true;
        }

        // Listen for user switches
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            IntentFilter ifUser = new IntentFilter();
            ifUser.addAction(Intent.ACTION_USER_BACKGROUND);
            ifUser.addAction(Intent.ACTION_USER_FOREGROUND);
            registerReceiver(userReceiver, ifUser);
            registeredUser = true;
        }

        // Listen for idle mode state changes
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            IntentFilter ifIdle = new IntentFilter();
            ifIdle.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
            registerReceiver(idleStateReceiver, ifIdle);
            registeredIdleState = true;
        }

        // Listen for added/removed applications
        IntentFilter ifPackage = new IntentFilter();
        ifPackage.addAction(Intent.ACTION_PACKAGE_ADDED);
        ifPackage.addAction(Intent.ACTION_PACKAGE_REMOVED);
        ifPackage.addDataScheme("package");
        registerReceiver(packageChangedReceiver, ifPackage);
        registeredPackageChanged = true;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            try {
                listenNetworkChanges();
            } catch (Throwable ex) {
                Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                listenConnectivityChanges();
            }
        else
            listenConnectivityChanges();

        // Monitor networks
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        cm.registerNetworkCallback(
                new NetworkRequest.Builder()
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(),
                networkMonitorCallback);

        // Setup house holding
        Intent alarmIntent = new Intent(this, ServiceSinkhole.class);
        alarmIntent.setAction(ACTION_HOUSE_HOLDING);
        PendingIntent pi;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            pi = PendingIntent.getForegroundService(this, 0, alarmIntent, PendingIntent.FLAG_UPDATE_CURRENT);
        else
            pi = PendingIntent.getService(this, 0, alarmIntent, PendingIntent.FLAG_UPDATE_CURRENT);

        AlarmManager am = (AlarmManager) getSystemService(Context.ALARM_SERVICE);
        am.setInexactRepeating(AlarmManager.RTC, SystemClock.elapsedRealtime() + 60 * 1000, AlarmManager.INTERVAL_HALF_DAY, pi);
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private void listenNetworkChanges() {
        // Listen for network changes
        Log.i(TAG, "Starting listening to network changes");
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkRequest.Builder builder = new NetworkRequest.Builder();
        builder.addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
        builder.addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED);

        ConnectivityManager.NetworkCallback nc = new ConnectivityManager.NetworkCallback() {
            private String last_generation = null;

            @Override
            public void onAvailable(Network network) {
                reload("network available", ServiceSinkhole.this, false);
            }

            @Override
            public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
                // Make sure the right DNS servers are being used
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                if (prefs.getBoolean("reload_onconnectivity", false) ||
                        Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                    reload("link properties changed", ServiceSinkhole.this, false);
            }

            @Override
            public void onCapabilitiesChanged(Network network, NetworkCapabilities networkCapabilities) {
                String current_generation = Util.getNetworkGeneration(ServiceSinkhole.this);
                Log.i(TAG, "Capabilities changed generation=" + current_generation);

                if (last_generation == null || !last_generation.equals(current_generation)) {
                    Log.i(TAG, "New network generation=" + current_generation);
                    last_generation = current_generation;

                    SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
                    if (prefs.getBoolean("unmetered_2g", false) ||
                            prefs.getBoolean("unmetered_3g", false) ||
                            prefs.getBoolean("unmetered_4g", false))
                        reload("data connection state changed", ServiceSinkhole.this, false);
                }
            }

            @Override
            public void onLost(Network network) {
                reload("network lost", ServiceSinkhole.this, false);
            }
        };
        cm.registerNetworkCallback(builder.build(), nc);
        networkCallback = nc;
    }

    private void listenConnectivityChanges() {
        // Listen for connectivity updates
        Log.i(TAG, "Starting listening to connectivity changes");
        IntentFilter ifConnectivity = new IntentFilter();
        ifConnectivity.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, ifConnectivity);
        registeredConnectivityChanged = true;

        // Listen for phone state changes
        Log.i(TAG, "Starting listening to service state changes");
        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        if (tm != null) {
            tm.listen(phoneStateListener, PhoneStateListener.LISTEN_DATA_CONNECTION_STATE);
            phone_state = true;
        }
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
                startForeground(NOTIFY_ENFORCING, getEnforcingNotification(-1, -1, -1));
            else if (state != State.none)
                startForeground(NOTIFY_WAITING, getWaitingNotification());
            Log.d(TAG, "Start foreground state=" + state.toString());
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (state == State.enforcing)
            startForeground(NOTIFY_ENFORCING, getEnforcingNotification(-1, -1, -1));
        else
            startForeground(NOTIFY_WAITING, getWaitingNotification());

        Log.i(TAG, "Received " + intent);
        Util.logExtras(intent);

        // Check for set command
        if (intent != null && intent.hasExtra(EXTRA_COMMAND) &&
                intent.getSerializableExtra(EXTRA_COMMAND) == Command.set) {
            set(intent);
            return START_STICKY;
        }

        // Keep awake
        getLock(this).acquire();

        // Get state
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean enabled = prefs.getBoolean("enabled", false);

        // Handle service restart
        if (intent == null) {
            Log.i(TAG, "Restart");

            // Recreate intent
            intent = new Intent(this, ServiceSinkhole.class);
            intent.putExtra(EXTRA_COMMAND, enabled ? Command.start : Command.stop);
        }

        if (ACTION_HOUSE_HOLDING.equals(intent.getAction()))
            intent.putExtra(EXTRA_COMMAND, Command.householding);
        if (ACTION_WATCHDOG.equals(intent.getAction()))
            intent.putExtra(EXTRA_COMMAND, Command.watchdog);

        Command cmd = (Command) intent.getSerializableExtra(EXTRA_COMMAND);
        if (cmd == null)
            intent.putExtra(EXTRA_COMMAND, enabled ? Command.start : Command.stop);
        String reason = intent.getStringExtra(EXTRA_REASON);
        Log.i(TAG, "Start intent=" + intent + " command=" + cmd + " reason=" + reason +
                " vpn=" + (vpn != null) + " user=" + (Process.myUid() / 100000));

        commandHandler.queue(intent);

        return START_STICKY;
    }

    private void set(Intent intent) {
        // Get arguments
        int uid = intent.getIntExtra(EXTRA_UID, 0);
        String network = intent.getStringExtra(EXTRA_NETWORK);
        String pkg = intent.getStringExtra(EXTRA_PACKAGE);
        boolean blocked = intent.getBooleanExtra(EXTRA_BLOCKED, false);
        Log.i(TAG, "Set " + pkg + " " + network + "=" + blocked);

        // Get defaults
        SharedPreferences settings = PreferenceManager.getDefaultSharedPreferences(ServiceSinkhole.this);
        boolean default_wifi = settings.getBoolean("whitelist_wifi", true);
        boolean default_other = settings.getBoolean("whitelist_other", true);

        // Update setting
        SharedPreferences prefs = getSharedPreferences(network, Context.MODE_PRIVATE);
        if (blocked == ("wifi".equals(network) ? default_wifi : default_other))
            prefs.edit().remove(pkg).apply();
        else
            prefs.edit().putBoolean(pkg, blocked).apply();

        // Apply rules
        ServiceSinkhole.reload("notification", ServiceSinkhole.this, false);

        // Update notification
        notifyNewApplication(uid);

        // Update UI
        Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
        LocalBroadcastManager.getInstance(ServiceSinkhole.this).sendBroadcast(ruleset);
    }

    @Override
    public void onRevoke() {
        Log.i(TAG, "Revoke");

        // Disable firewall (will result in stop command)
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.edit().putBoolean("enabled", false).apply();

        // Feedback
        showDisabledNotification();
        WidgetMain.updateWidgets(this);

        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        synchronized (this) {
            Log.i(TAG, "Destroy");
            commandLooper.quit();
            logLooper.quit();
            statsLooper.quit();

            for (Command command : Command.values())
                commandHandler.removeMessages(command.ordinal());
            releaseLock(this);

            // Registered in command loop
            if (registeredInteractiveState) {
                unregisterReceiver(interactiveStateReceiver);
                registeredInteractiveState = false;
            }
            if (callStateListener != null) {
                TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
                tm.listen(callStateListener, PhoneStateListener.LISTEN_NONE);
                callStateListener = null;
            }

            // Register in onCreate
            if (registeredPowerSave) {
                unregisterReceiver(powerSaveReceiver);
                registeredPowerSave = false;
            }
            if (registeredUser) {
                unregisterReceiver(userReceiver);
                registeredUser = false;
            }
            if (registeredIdleState) {
                unregisterReceiver(idleStateReceiver);
                registeredIdleState = false;
            }
            if (registeredPackageChanged) {
                unregisterReceiver(packageChangedReceiver);
                registeredPackageChanged = false;
            }

            if (networkCallback != null) {
                unlistenNetworkChanges();
                networkCallback = null;
            }
            if (registeredConnectivityChanged) {
                unregisterReceiver(connectivityChangedReceiver);
                registeredConnectivityChanged = false;
            }

            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            cm.unregisterNetworkCallback(networkMonitorCallback);

            if (phone_state) {
                TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
                tm.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE);
                phone_state = false;
            }

            try {
                if (vpn != null) {
                    stopNative(vpn, true);
                    stopVPN(vpn);
                    vpn = null;
                    unprepare();
                }
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

            jni_done(jni_context);

            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.unregisterOnSharedPreferenceChangeListener(this);
        }

        super.onDestroy();
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private void unlistenNetworkChanges() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        cm.unregisterNetworkCallback((ConnectivityManager.NetworkCallback) networkCallback);
    }

    private Notification getEnforcingNotification(int allowed, int blocked, int hosts) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "foreground");
        builder.setSmallIcon(isLockedDown(last_metered) ? R.drawable.ic_lock_outline_white_24dp : R.drawable.ic_security_white_24dp)
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(true)
                .setAutoCancel(false);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            builder.setContentTitle(getString(R.string.msg_started));
        else
            builder.setContentTitle(getString(R.string.app_name))
                    .setContentText(getString(R.string.msg_started));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET)
                    .setPriority(NotificationCompat.PRIORITY_MIN);

        if (allowed >= 0)
            last_allowed = allowed;
        else
            allowed = last_allowed;
        if (blocked >= 0)
            last_blocked = blocked;
        else
            blocked = last_blocked;
        if (hosts >= 0)
            last_hosts = hosts;
        else
            hosts = last_hosts;

        if (allowed >= 0 || blocked >= 0 || hosts >= 0) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                if (Util.isPlayStoreInstall(this))
                    builder.setContentText(getString(R.string.msg_packages, allowed, blocked));
                else
                    builder.setContentText(getString(R.string.msg_hosts, allowed, blocked, hosts));
                return builder.build();
            } else {
                NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
                notification.bigText(getString(R.string.msg_started));
                if (Util.isPlayStoreInstall(this))
                    notification.setSummaryText(getString(R.string.msg_packages, allowed, blocked));
                else
                    notification.setSummaryText(getString(R.string.msg_hosts, allowed, blocked, hosts));
                return notification.build();
            }
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
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "foreground");
        builder.setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(true)
                .setAutoCancel(false);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            builder.setContentTitle(getString(R.string.msg_waiting));
        else
            builder.setContentTitle(getString(R.string.app_name))
                    .setContentText(getString(R.string.msg_waiting));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET)
                    .setPriority(NotificationCompat.PRIORITY_MIN);

        return builder.build();
    }

    private void showDisabledNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
        builder.setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_revoked))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_revoked));

        NotificationManagerCompat.from(this).notify(NOTIFY_DISABLED, notification.build());
    }

    private void showAutoStartNotification() {
        Intent main = new Intent(this, ActivityMain.class);
        main.putExtra(ActivityMain.EXTRA_APPROVE, true);
        PendingIntent pi = PendingIntent.getActivity(this, NOTIFY_AUTOSTART, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
        builder.setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_autostart))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_autostart));

        NotificationManagerCompat.from(this).notify(NOTIFY_AUTOSTART, notification.build());
    }

    private void showErrorNotification(String message) {
        Intent main = new Intent(this, ActivityMain.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
        builder.setSmallIcon(R.drawable.ic_error_white_24dp)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.msg_error, message))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        NotificationCompat.BigTextStyle notification = new NotificationCompat.BigTextStyle(builder);
        notification.bigText(getString(R.string.msg_error, message));
        notification.setSummaryText(message);

        NotificationManagerCompat.from(this).notify(NOTIFY_ERROR, notification.build());
    }

    private void showAccessNotification(int uid) {
        String name = TextUtils.join(", ", Util.getApplicationNames(uid, ServiceSinkhole.this));

        Intent main = new Intent(ServiceSinkhole.this, ActivityMain.class);
        main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
        PendingIntent pi = PendingIntent.getActivity(ServiceSinkhole.this, uid + 10000, main, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        int colorOn = tv.data;
        getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        int colorOff = tv.data;

        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "access");
        builder.setSmallIcon(R.drawable.ic_cloud_upload_white_24dp)
                .setGroup("AccessAttempt")
                .setContentIntent(pi)
                .setColor(colorOff)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            builder.setContentTitle(name)
                    .setContentText(getString(R.string.msg_access_n));
        else
            builder.setContentTitle(getString(R.string.app_name))
                    .setContentText(getString(R.string.msg_access, name));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        DateFormat df = new SimpleDateFormat("dd HH:mm");

        NotificationCompat.InboxStyle notification = new NotificationCompat.InboxStyle(builder);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            notification.addLine(getString(R.string.msg_access_n));
        else {
            String sname = getString(R.string.msg_access, name);
            int pos = sname.indexOf(name);
            Spannable sp = new SpannableString(sname);
            sp.setSpan(new StyleSpan(Typeface.BOLD), pos, pos + name.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            notification.addLine(sp);
        }

        long since = 0;
        PackageManager pm = getPackageManager();
        String[] packages = pm.getPackagesForUid(uid);
        if (packages != null && packages.length > 0)
            try {
                since = pm.getPackageInfo(packages[0], 0).firstInstallTime;
            } catch (PackageManager.NameNotFoundException ignored) {
            }

        Cursor cursor = DatabaseHelper.getInstance(ServiceSinkhole.this).getAccessUnset(uid, 7, since);
        int colDAddr = cursor.getColumnIndex("daddr");
        int colTime = cursor.getColumnIndex("time");
        int colAllowed = cursor.getColumnIndex("allowed");
        while (cursor.moveToNext()) {
            StringBuilder sb = new StringBuilder();
            sb.append(df.format(cursor.getLong(colTime))).append(' ');

            String daddr = cursor.getString(colDAddr);
            if (Util.isNumericAddress(daddr))
                try {
                    daddr = InetAddress.getByName(daddr).getHostName();
                } catch (UnknownHostException ignored) {
                }
            sb.append(daddr);

            int allowed = cursor.getInt(colAllowed);
            if (allowed >= 0) {
                int pos = sb.indexOf(daddr);
                Spannable sp = new SpannableString(sb);
                ForegroundColorSpan fgsp = new ForegroundColorSpan(allowed > 0 ? colorOn : colorOff);
                sp.setSpan(fgsp, pos, pos + daddr.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                notification.addLine(sp);
            } else
                notification.addLine(sb);
        }
        cursor.close();

        NotificationManagerCompat.from(this).notify(uid + 10000, notification.build());
    }

    private void showUpdateNotification(String name, String url) {
        Intent download = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
        PendingIntent pi = PendingIntent.getActivity(this, 0, download, PendingIntent.FLAG_UPDATE_CURRENT);

        TypedValue tv = new TypedValue();
        getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        NotificationCompat.Builder builder = new NotificationCompat.Builder(this, "notify");
        builder.setSmallIcon(R.drawable.ic_security_white_24dp)
                .setContentTitle(name)
                .setContentText(getString(R.string.msg_update))
                .setContentIntent(pi)
                .setColor(tv.data)
                .setOngoing(false)
                .setAutoCancel(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            builder.setCategory(NotificationCompat.CATEGORY_STATUS)
                    .setVisibility(NotificationCompat.VISIBILITY_SECRET);

        NotificationManagerCompat.from(this).notify(NOTIFY_UPDATE, builder.build());
    }

    private void removeWarningNotifications() {
        NotificationManagerCompat.from(this).cancel(NOTIFY_DISABLED);
        NotificationManagerCompat.from(this).cancel(NOTIFY_AUTOSTART);
        NotificationManagerCompat.from(this).cancel(NOTIFY_ERROR);
    }

    private class Builder extends VpnService.Builder {
        private NetworkInfo networkInfo;
        private int mtu;
        private List<String> listAddress = new ArrayList<>();
        private List<String> listRoute = new ArrayList<>();
        private List<InetAddress> listDns = new ArrayList<>();
        private List<String> listDisallowed = new ArrayList<>();

        private Builder() {
            super();
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            networkInfo = cm.getActiveNetworkInfo();
        }

        @Override
        public VpnService.Builder setMtu(int mtu) {
            this.mtu = mtu;
            super.setMtu(mtu);
            return this;
        }

        @Override
        public Builder addAddress(String address, int prefixLength) {
            listAddress.add(address + "/" + prefixLength);
            super.addAddress(address, prefixLength);
            return this;
        }

        @Override
        public Builder addRoute(String address, int prefixLength) {
            listRoute.add(address + "/" + prefixLength);
            super.addRoute(address, prefixLength);
            return this;
        }

        @Override
        public Builder addDnsServer(InetAddress address) {
            listDns.add(address);
            super.addDnsServer(address);
            return this;
        }

        @Override
        public Builder addDisallowedApplication(String packageName) throws PackageManager.NameNotFoundException {
            listDisallowed.add(packageName);
            super.addDisallowedApplication(packageName);
            return this;
        }

        @Override
        public boolean equals(Object obj) {
            Builder other = (Builder) obj;

            if (other == null)
                return false;

            if (this.networkInfo == null || other.networkInfo == null ||
                    this.networkInfo.getType() != other.networkInfo.getType())
                return false;

            if (this.mtu != other.mtu)
                return false;

            if (this.listAddress.size() != other.listAddress.size())
                return false;

            if (this.listRoute.size() != other.listRoute.size())
                return false;

            if (this.listDns.size() != other.listDns.size())
                return false;

            if (this.listDisallowed.size() != other.listDisallowed.size())
                return false;

            for (String address : this.listAddress)
                if (!other.listAddress.contains(address))
                    return false;

            for (String route : this.listRoute)
                if (!other.listRoute.contains(route))
                    return false;

            for (InetAddress dns : this.listDns)
                if (!other.listDns.contains(dns))
                    return false;

            for (String pkg : this.listDisallowed)
                if (!other.listDisallowed.contains(pkg))
                    return false;

            return true;
        }
    }

    private class IPRule {
        private boolean block;
        private long expires;

        public IPRule(boolean block, long expires) {
            this.block = block;
            this.expires = expires;
        }

        public boolean isBlocked() {
            return this.block;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > this.expires;
        }

        public void updateExpires(long expires) {
            this.expires = Math.max(this.expires, expires);
        }

        @Override
        public boolean equals(Object obj) {
            IPRule other = (IPRule) obj;
            return (this.block == other.block && this.expires == other.expires);
        }
    }

    public static void run(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.run);
        intent.putExtra(EXTRA_REASON, reason);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void start(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.start);
        intent.putExtra(EXTRA_REASON, reason);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void reload(String reason, Context context, boolean interactive) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        if (prefs.getBoolean("enabled", false)) {
            Intent intent = new Intent(context, ServiceSinkhole.class);
            intent.putExtra(EXTRA_COMMAND, Command.reload);
            intent.putExtra(EXTRA_REASON, reason);
            intent.putExtra(EXTRA_INTERACTIVE, interactive);
            ContextCompat.startForegroundService(context, intent);
        }
    }

    public static void stop(String reason, Context context, boolean vpnonly) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.stop);
        intent.putExtra(EXTRA_REASON, reason);
        intent.putExtra(EXTRA_TEMPORARY, vpnonly);
        ContextCompat.startForegroundService(context, intent);
    }

    public static void reloadStats(String reason, Context context) {
        Intent intent = new Intent(context, ServiceSinkhole.class);
        intent.putExtra(EXTRA_COMMAND, Command.stats);
        intent.putExtra(EXTRA_REASON, reason);
        ContextCompat.startForegroundService(context, intent);
    }
}
