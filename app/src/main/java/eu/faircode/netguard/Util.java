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

import android.Manifest;
import android.annotation.TargetApi;
import android.app.ApplicationErrorReport;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkInfo;
import android.net.Uri;
import android.net.VpnService;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Util {
    private static final int NETWORK_TYPE_TD_SCDMA = 17;
    private static final int NETWORK_TYPE_IWLAN = 18;
    private static final String TAG = "NetGuard.Util";

    public static String getSelfVersionName(Context context) {
        try {
            PackageInfo pInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return pInfo.versionName;
        } catch (PackageManager.NameNotFoundException ex) {
            return ex.toString();
        }
    }

    public static int getSelfVersionCode(Context context) {
        try {
            PackageInfo pInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
            return pInfo.versionCode;
        } catch (PackageManager.NameNotFoundException ex) {
            return -1;
        }
    }

    public static boolean hasTelephony(Context context) {
        PackageManager pm = context.getPackageManager();
        return pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY);
    }

    public static boolean hasWifi(Context context) {
        PackageManager pm = context.getPackageManager();
        return pm.hasSystemFeature(PackageManager.FEATURE_WIFI);
    }

    public static boolean isConnected(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = cm.getActiveNetworkInfo();
        return (ni != null && ni.isConnected());
    }

    public static boolean isWifiActive(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = cm.getActiveNetworkInfo();
        return (ni != null && ni.getType() == ConnectivityManager.TYPE_WIFI);
    }

    public static boolean isMeteredNetwork(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        return cm.isActiveNetworkMetered();
    }

    public static String getWifiSSID(Context context) {
        WifiManager wm = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        String ssid = wm.getConnectionInfo().getSSID();
        return (ssid == null ? "NULL" : ssid);
    }

    public static int getNetworkType(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = cm.getActiveNetworkInfo();
        return (ni == null ? TelephonyManager.NETWORK_TYPE_UNKNOWN : ni.getSubtype());
    }

    public static String getNetworkGeneration(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = cm.getActiveNetworkInfo();
        return (ni != null && ni.getType() == ConnectivityManager.TYPE_MOBILE ? getNetworkGeneration(ni.getSubtype()) : null);
    }

    public static boolean isRoaming(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = cm.getActiveNetworkInfo();
        return (ni != null && ni.isRoaming());
    }

    public static boolean isInternational(Context context) {
        TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1
                && hasPhoneStatePermission(context)) {
            int dataSubId;
            try {
                dataSubId = Settings.Global.getInt(context.getContentResolver(), "multi_sim_data_call", -1);
            } catch (Throwable ignored) {
                dataSubId = -1;
            }
            if (dataSubId >= 0) {
                SubscriptionManager sm = SubscriptionManager.from(context);
                SubscriptionInfo si = sm.getActiveSubscriptionInfo(dataSubId);
                if (si != null && si.getCountryIso() != null)
                    try {
                        Method getNetworkCountryIso = tm.getClass().getMethod("getNetworkCountryIsoForSubscription", int.class);
                        getNetworkCountryIso.setAccessible(true);
                        String networkCountryIso = (String) getNetworkCountryIso.invoke(tm, dataSubId);
                        Log.d(TAG, "SIM=" + si.getCountryIso() + " network=" + networkCountryIso);
                        return !si.getCountryIso().equals(networkCountryIso);
                    } catch (Throwable ex) {
                        Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        sendCrashReport(ex, context);
                    }
            }
        }

        return (tm.getSimCountryIso() == null ? true : !tm.getSimCountryIso().equals(tm.getNetworkCountryIso()));
    }

    public static String getNetworkGeneration(int networkType) {
        switch (networkType) {
            case TelephonyManager.NETWORK_TYPE_1xRTT:
            case TelephonyManager.NETWORK_TYPE_CDMA:
            case TelephonyManager.NETWORK_TYPE_EDGE:
            case TelephonyManager.NETWORK_TYPE_GPRS:
            case TelephonyManager.NETWORK_TYPE_IDEN:
                return "2G";

            case TelephonyManager.NETWORK_TYPE_EHRPD:
            case TelephonyManager.NETWORK_TYPE_EVDO_0:
            case TelephonyManager.NETWORK_TYPE_EVDO_A:
            case TelephonyManager.NETWORK_TYPE_EVDO_B:
            case TelephonyManager.NETWORK_TYPE_HSDPA:
            case TelephonyManager.NETWORK_TYPE_HSPA:
            case TelephonyManager.NETWORK_TYPE_HSPAP:
            case TelephonyManager.NETWORK_TYPE_HSUPA:
            case TelephonyManager.NETWORK_TYPE_UMTS:
            case NETWORK_TYPE_TD_SCDMA:
                return "3G";

            case TelephonyManager.NETWORK_TYPE_LTE:
            case NETWORK_TYPE_IWLAN:
                return "4G";

            default:
                return "?G";
        }
    }

    public static String getNetworkTypeName(int networkType) {
        switch (networkType) {
            // 2G
            case TelephonyManager.NETWORK_TYPE_1xRTT:
                return "1xRTT";
            case TelephonyManager.NETWORK_TYPE_CDMA:
                return "CDMA";
            case TelephonyManager.NETWORK_TYPE_EDGE:
                return "EDGE";
            case TelephonyManager.NETWORK_TYPE_GPRS:
                return "GPRS";
            case TelephonyManager.NETWORK_TYPE_IDEN:
                return "IDEN";

            // 3G
            case TelephonyManager.NETWORK_TYPE_EHRPD:
                return "EHRPD";
            case TelephonyManager.NETWORK_TYPE_EVDO_0:
                return "EVDO_0";
            case TelephonyManager.NETWORK_TYPE_EVDO_A:
                return "EVDO_A";
            case TelephonyManager.NETWORK_TYPE_EVDO_B:
                return "EVDO_B";
            case TelephonyManager.NETWORK_TYPE_HSDPA:
                return "HSDPA";
            case TelephonyManager.NETWORK_TYPE_HSPA:
                return "HSPA";
            case TelephonyManager.NETWORK_TYPE_HSPAP:
                return "HSPAP";
            case TelephonyManager.NETWORK_TYPE_HSUPA:
                return "HSUPA";
            case TelephonyManager.NETWORK_TYPE_UMTS:
                return "UMTS";
            case NETWORK_TYPE_TD_SCDMA:
                return "TD_SCDMA";

            // 4G
            case TelephonyManager.NETWORK_TYPE_LTE:
                return "LTE";
            case NETWORK_TYPE_IWLAN:
                return "IWLAN";

            default:
                return Integer.toString(networkType);
        }
    }

    public static String getPhoneTypeName(int phoneType) {
        switch (phoneType) {
            case TelephonyManager.PHONE_TYPE_NONE:
                return "None";
            case TelephonyManager.PHONE_TYPE_GSM:
                return "GSM";
            case TelephonyManager.PHONE_TYPE_CDMA:
                return "CDMA";
            case TelephonyManager.PHONE_TYPE_SIP:
                return "SIP";
            default:
                return "Unknown";
        }
    }

    public static boolean hasPhoneStatePermission(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            return (context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED);
        else
            return true;
    }

    public static boolean isInteractive(Context context) {
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        return pm.isInteractive();
    }

    public static boolean isPackageInstalled(String packageName, Context context) {
        try {
            context.getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    public static boolean isDebuggable(Context context) {
        return ((context.getApplicationContext().getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
    }

    public static boolean isPlayStoreInstall(Context context) {
        return "com.android.vending".equals(context.getPackageManager().getInstallerPackageName(context.getPackageName()));
    }

    public static boolean hasValidFingerprint(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            String pkg = context.getPackageName();
            PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
            byte[] cert = info.signatures[0].toByteArray();
            MessageDigest digest = MessageDigest.getInstance("SHA1");
            byte[] bytes = digest.digest(cert);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; ++i)
                sb.append(Integer.toString(bytes[i] & 0xff, 16).toLowerCase());
            String calculated = sb.toString();
            String expected = context.getString(R.string.fingerprint);
            return calculated.equals(expected);
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            return false;
        }
    }

    public static int dips2pixels(int dips, Context context) {
        return Math.round(dips * context.getResources().getDisplayMetrics().density + 0.5f);
    }

    public static void logExtras(Intent intent) {
        if (intent != null)
            logBundle(intent.getExtras());
    }

    public static void logBundle(Bundle data) {
        if (data != null) {
            Set<String> keys = data.keySet();
            StringBuilder stringBuilder = new StringBuilder();
            for (String key : keys) {
                Object value = data.get(key);
                stringBuilder.append(key)
                        .append("=")
                        .append(value)
                        .append(value == null ? "" : " (" + value.getClass().getSimpleName() + ")")
                        .append("\r\n");
            }
            Log.d(TAG, stringBuilder.toString());
        }
    }

    public static void sendCrashReport(Throwable ex, final Context context) {
        try {
            ApplicationErrorReport report = new ApplicationErrorReport();
            report.packageName = report.processName = context.getPackageName();
            report.time = System.currentTimeMillis();
            report.type = ApplicationErrorReport.TYPE_CRASH;
            report.systemApp = false;

            ApplicationErrorReport.CrashInfo crash = new ApplicationErrorReport.CrashInfo();
            crash.exceptionClassName = ex.getClass().getSimpleName();
            crash.exceptionMessage = ex.getMessage();

            StringWriter writer = new StringWriter();
            PrintWriter printer = new PrintWriter(writer);
            ex.printStackTrace(printer);

            crash.stackTrace = writer.toString();

            StackTraceElement stack = ex.getStackTrace()[0];
            crash.throwClassName = stack.getClassName();
            crash.throwFileName = stack.getFileName();
            crash.throwLineNumber = stack.getLineNumber();
            crash.throwMethodName = stack.getMethodName();

            report.crashInfo = crash;

            final Intent bug = new Intent(Intent.ACTION_APP_ERROR);
            bug.putExtra(Intent.EXTRA_BUG_REPORT, report);
            bug.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            if (bug.resolveActivity(context.getPackageManager()) != null)
                context.startActivity(bug);
        } catch (Throwable exex) {
            Log.e(TAG, exex.toString() + "\n" + Log.getStackTraceString(exex));
        }
    }

    public static String getGeneralInfo(Context context) {
        StringBuilder sb = new StringBuilder();
        TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);

        sb.append(String.format("Interactive %B\r\n", isInteractive(context)));
        sb.append(String.format("Telephony %B\r\n", hasTelephony(context)));
        sb.append(String.format("Connected %B\r\n", isConnected(context)));
        sb.append(String.format("WiFi %B\r\n", isWifiActive(context)));
        sb.append(String.format("Metered %B\r\n", isMeteredNetwork(context)));
        sb.append(String.format("Roaming %B\r\n", isRoaming(context)));

        sb.append(String.format("Type %s\r\n", getPhoneTypeName(tm.getPhoneType())));

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1
                || !hasPhoneStatePermission(context)) {
            if (tm.getSimState() == TelephonyManager.SIM_STATE_READY)
                sb.append(String.format("SIM %s/%s/%s\r\n", tm.getSimCountryIso(), tm.getSimOperatorName(), tm.getSimOperator()));
            if (tm.getNetworkType() != TelephonyManager.NETWORK_TYPE_UNKNOWN)
                sb.append(String.format("Network %s/%s/%s\r\n", tm.getNetworkCountryIso(), tm.getNetworkOperatorName(), tm.getNetworkOperator()));
        }

        if (sb.length() > 2)
            sb.setLength(sb.length() - 2);

        return sb.toString();
    }

    public static String getNetworkInfo(Context context) {
        StringBuilder sb = new StringBuilder();
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

        NetworkInfo ani = cm.getActiveNetworkInfo();
        for (Network network : cm.getAllNetworks()) {
            NetworkInfo ni = cm.getNetworkInfo(network);
            if (ni != null)
                sb.append(ni.getTypeName())
                        .append('/')
                        .append(ni.getSubtypeName())
                        .append(' ').append(ni.getDetailedState())
                        .append(TextUtils.isEmpty(ni.getExtraInfo()) ? "" : " " + ni.getExtraInfo())
                        .append(ni.getType() == ConnectivityManager.TYPE_MOBILE ? " " + Util.getNetworkGeneration(ni.getSubtype()) : "")
                        .append(ni.isRoaming() ? " R" : "")
                        .append(ani != null && ni.getType() == ani.getType() && ni.getSubtype() == ani.getSubtype() ? " *" : "")
                        .append("\r\n");
        }

        if (sb.length() > 2)
            sb.setLength(sb.length() - 2);

        return sb.toString();
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP_MR1)
    public static String getSubscriptionInfo(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1)
            return "Not supported";
        if (!hasPhoneStatePermission(context))
            return "No permission";

        StringBuilder sb = new StringBuilder();
        SubscriptionManager sm = SubscriptionManager.from(context);
        TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);

        sb.append("Slots ")
                .append(sm.getActiveSubscriptionInfoCount())
                .append('/')
                .append(sm.getActiveSubscriptionInfoCountMax())
                .append("\r\n");

        int dataSubId;
        try {
            dataSubId = Settings.Global.getInt(context.getContentResolver(), "multi_sim_data_call", -1);
        } catch (Throwable ignored) {
            dataSubId = -1;
        }

        Method getNetworkCountryIso = null;
        Method getNetworkOperator = null;
        Method getNetworkOperatorName = null;
        Method getDataEnabled = null;
        try {
            getNetworkCountryIso = tm.getClass().getMethod("getNetworkCountryIsoForSubscription", int.class);
            getNetworkOperator = tm.getClass().getMethod("getNetworkOperatorForSubscription", int.class);
            getNetworkOperatorName = tm.getClass().getMethod("getNetworkOperatorName", int.class);
            getDataEnabled = tm.getClass().getMethod("getDataEnabled", int.class);

            getNetworkCountryIso.setAccessible(true);
            getNetworkOperator.setAccessible(true);
            getNetworkOperatorName.setAccessible(true);
            getDataEnabled.setAccessible(true);
        } catch (NoSuchMethodException ex) {
            Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        List<SubscriptionInfo> subscriptions = sm.getActiveSubscriptionInfoList();
        if (subscriptions != null)
            for (SubscriptionInfo si : subscriptions) {
                sb.append("SIM ")
                        .append(si.getSimSlotIndex() + 1)
                        .append('/')
                        .append(si.getSubscriptionId())
                        .append(' ')
                        .append(si.getCountryIso())
                        .append('/')
                        .append(si.getMcc()).append(si.getMnc())
                        .append(' ')
                        .append(si.getCarrierName())
                        .append(si.getDataRoaming() == SubscriptionManager.DATA_ROAMING_ENABLE ? " R" : "")
                        .append(si.getSubscriptionId() == dataSubId ? " *" : "")
                        .append("\r\n");
                if (getNetworkCountryIso != null &&
                        getNetworkOperator != null &&
                        getNetworkOperatorName != null &&
                        getDataEnabled != null)
                    try {
                        sb.append("Network ")
                                .append(si.getSimSlotIndex() + 1)
                                .append('/')
                                .append(si.getSubscriptionId())
                                .append(' ')
                                .append(getNetworkCountryIso.invoke(tm, si.getSubscriptionId()))
                                .append('/')
                                .append(getNetworkOperator.invoke(tm, si.getSubscriptionId()))
                                .append(' ')
                                .append(getNetworkOperatorName.invoke(tm, si.getSubscriptionId()))
                                .append(sm.isNetworkRoaming(si.getSubscriptionId()) ? " R" : "")
                                .append(' ')
                                .append(String.format("%B", getDataEnabled.invoke(tm, si.getSubscriptionId())))
                                .append("\r\n");
                    } catch (IllegalAccessException ex) {
                        Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    } catch (InvocationTargetException ex) {
                        Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
            }

        if (sb.length() > 2)
            sb.setLength(sb.length() - 2);

        return sb.toString();
    }

    public static void sendLogcat(final Uri uri, final Context context) {
        AsyncTask task = new AsyncTask<Object, Object, Intent>() {
            @Override
            protected Intent doInBackground(Object... objects) {
                // Get device info
                StringBuilder sb = new StringBuilder();
                String version = getSelfVersionName(context);
                sb.append(String.format("NetGuard: %s/%d\r\n", version, getSelfVersionCode(context)));
                sb.append(String.format("Android: %s (SDK %d)\r\n", Build.VERSION.RELEASE, Build.VERSION.SDK_INT));
                sb.append("\r\n");

                sb.append(String.format("Brand: %s\r\n", Build.BRAND));
                sb.append(String.format("Manufacturer: %s\r\n", Build.MANUFACTURER));
                sb.append(String.format("Model: %s\r\n", Build.MODEL));
                sb.append(String.format("Product: %s\r\n", Build.PRODUCT));
                sb.append(String.format("Device: %s\r\n", Build.DEVICE));
                sb.append(String.format("Host: %s\r\n", Build.HOST));
                sb.append(String.format("Display: %s\r\n", Build.DISPLAY));
                sb.append(String.format("Id: %s\r\n", Build.ID));
                sb.append(String.format("Fingerprint: %B\r\n", hasValidFingerprint(context)));
                sb.append("\r\n");

                sb.append(String.format("VPN dialogs: %B\r\n", isPackageInstalled("com.android.vpndialogs", context)));
                try {
                    sb.append(String.format("Prepared: %B\r\n", VpnService.prepare(context) == null));
                } catch (Throwable ex) {
                    sb.append("Prepared: ").append((ex.toString())).append("\r\n").append(Log.getStackTraceString(ex));
                }
                sb.append(String.format("Permission: %B\r\n", hasPhoneStatePermission(context)));
                sb.append("\r\n");

                sb.append(getGeneralInfo(context));
                sb.append("\r\n\r\n");
                sb.append(getNetworkInfo(context));
                sb.append("\r\n\r\n");
                sb.append(getSubscriptionInfo(context));
                sb.append("\r\n\r\n");

                // Get settings
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
                Map<String, ?> all = prefs.getAll();
                for (String key : all.keySet())
                    sb.append("Setting: ").append(key).append('=').append(all.get(key)).append("\r\n");
                sb.append("\r\n");

                // Finalize message
                sb.append("Please describe your problem:\r\n");
                sb.append("\r\n");

                // Write logcat
                OutputStream out = null;
                try {
                    Log.i(TAG, "Writing logcat URI=" + uri);
                    out = context.getContentResolver().openOutputStream(uri);
                    out.write(getLogcat().toString().getBytes());
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    sb.append(ex.toString()).append("\r\n").append(Log.getStackTraceString(ex)).append("\r\n");
                } finally {
                    if (out != null)
                        try {
                            out.close();
                        } catch (IOException ignored) {
                        }
                }

                // Build intent
                Intent sendEmail = new Intent(Intent.ACTION_SEND);
                sendEmail.setType("message/rfc822");
                sendEmail.putExtra(Intent.EXTRA_EMAIL, new String[]{"marcel+netguard@faircode.eu"});
                sendEmail.putExtra(Intent.EXTRA_SUBJECT, "NetGuard " + version + " logcat");
                sendEmail.putExtra(Intent.EXTRA_TEXT, sb.toString());
                sendEmail.putExtra(Intent.EXTRA_STREAM, uri);
                return sendEmail;
            }

            @Override
            protected void onPostExecute(Intent sendEmail) {
                if (sendEmail != null)
                    try {
                        context.startActivity(sendEmail);
                    } catch (Throwable ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
            }
        };
        task.execute();
    }

    private static StringBuilder getLogcat() {
        String pid = Integer.toString(android.os.Process.myPid());
        StringBuilder builder = new StringBuilder();
        Process process = null;
        BufferedReader br = null;
        try {
            String[] command = new String[]{"logcat", "-d", "-v", "threadtime"};
            process = Runtime.getRuntime().exec(command);
            br = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = br.readLine()) != null)
                if (line.toLowerCase().contains("netguard"))
                    builder.append(line).append("\r\n");
        } catch (IOException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        } finally {
            if (br != null)
                try {
                    br.close();
                } catch (IOException ignored) {
                }
            if (process != null)
                process.destroy();
        }
        return builder;
    }
}
