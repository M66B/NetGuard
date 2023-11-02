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

    Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.ApplicationErrorReport;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Log;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.core.app.ActivityCompat;
import androidx.core.net.ConnectivityManagerCompat;
import androidx.preference.PreferenceManager;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Util {
    private static final String TAG = "NetGuard.Util";

    // Roam like at home
    private static final List<String> listEU = Arrays.asList(
            "AT", // Austria
            "BE", // Belgium
            "BG", // Bulgaria
            "HR", // Croatia
            "CY", // Cyprus
            "CZ", // Czech Republic
            "DK", // Denmark
            "EE", // Estonia
            "FI", // Finland
            "FR", // France
            "DE", // Germany
            "GR", // Greece
            "HU", // Hungary
            "IS", // Iceland
            "IE", // Ireland
            "IT", // Italy
            "LV", // Latvia
            "LI", // Liechtenstein
            "LT", // Lithuania
            "LU", // Luxembourg
            "MT", // Malta
            "NL", // Netherlands
            "NO", // Norway
            "PL", // Poland
            "PT", // Portugal
            "RE", // La Réunion
            "RO", // Romania
            "SK", // Slovakia
            "SI", // Slovenia
            "ES", // Spain
            "SE" // Sweden
    );

    private static native String jni_getprop(String name);

    private static native boolean is_numeric_address(String ip);

    private static native void dump_memory_profile();

    static {
        try {
            System.loadLibrary("netguard");
        } catch (UnsatisfiedLinkError ignored) {
            System.exit(1);
        }
    }

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

    public static boolean isNetworkActive(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        return (cm != null && cm.getActiveNetworkInfo() != null);
    }

    public static boolean isConnected(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null)
            return false;

        NetworkInfo ni = cm.getActiveNetworkInfo();
        if (ni != null && ni.isConnected())
            return true;

        return false;
    }

    public static boolean isWifiActive(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = (cm == null ? null : cm.getActiveNetworkInfo());
        return (ni != null && ni.getType() == ConnectivityManager.TYPE_WIFI);
    }

    public static boolean isMeteredNetwork(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        return (cm != null && ConnectivityManagerCompat.isActiveNetworkMetered(cm));
    }

    public static String getWifiSSID(Context context) {
        WifiManager wm = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        String ssid = (wm == null ? null : wm.getConnectionInfo().getSSID());
        return (ssid == null ? "NULL" : ssid);
    }

    public static int getNetworkType(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = (cm == null ? null : cm.getActiveNetworkInfo());
        return (ni == null ? TelephonyManager.NETWORK_TYPE_UNKNOWN : ni.getSubtype());
    }

    public static String getNetworkGeneration(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = cm.getActiveNetworkInfo();
        return (ni != null && ni.getType() == ConnectivityManager.TYPE_MOBILE ? getNetworkGeneration(ni.getSubtype()) : null);
    }

    public static boolean isRoaming(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo ni = (cm == null ? null : cm.getActiveNetworkInfo());
        return (ni != null && ni.isRoaming());
    }

    public static boolean isNational(Context context) {
        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            return (tm != null && tm.getSimCountryIso() != null && tm.getSimCountryIso().equals(tm.getNetworkCountryIso()));
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean isEU(Context context) {
        try {
            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            return (tm != null && isEU(tm.getSimCountryIso()) && isEU(tm.getNetworkCountryIso()));
        } catch (Throwable ignored) {
            return false;
        }
    }

    public static boolean isEU(String country) {
        return (country != null && listEU.contains(country.toUpperCase()));
    }

    public static boolean isPrivateDns(Context context) {
        String dns_mode = Settings.Global.getString(context.getContentResolver(), "private_dns_mode");
        Log.i(TAG, "Private DNS mode=" + dns_mode);
        if (dns_mode == null)
            dns_mode = "off";
        return (!"off".equals(dns_mode));
    }

    public static String getPrivateDnsSpecifier(Context context) {
        String dns_mode = Settings.Global.getString(context.getContentResolver(), "private_dns_mode");
        if ("hostname".equals(dns_mode))
            return Settings.Global.getString(context.getContentResolver(), "private_dns_specifier");
        else
            return null;
    }

    public static String getNetworkGeneration(int networkType) {
        switch (networkType) {
            case TelephonyManager.NETWORK_TYPE_1xRTT:
            case TelephonyManager.NETWORK_TYPE_CDMA:
            case TelephonyManager.NETWORK_TYPE_EDGE:
            case TelephonyManager.NETWORK_TYPE_GPRS:
            case TelephonyManager.NETWORK_TYPE_IDEN:
            case TelephonyManager.NETWORK_TYPE_GSM:
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
            case TelephonyManager.NETWORK_TYPE_TD_SCDMA:
                return "3G";

            case TelephonyManager.NETWORK_TYPE_LTE:
            case TelephonyManager.NETWORK_TYPE_IWLAN:
                return "4G";

            default:
                return "?G";
        }
    }

    public static boolean hasPhoneStatePermission(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            return (context.checkSelfPermission(Manifest.permission.READ_PHONE_STATE) == PackageManager.PERMISSION_GRANTED);
        else
            return true;
    }

    public static List<String> getDefaultDNS(Context context) {
        List<String> listDns = new ArrayList<>();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            Network an = cm.getActiveNetwork();
            if (an != null) {
                LinkProperties lp = cm.getLinkProperties(an);
                if (lp != null) {
                    List<InetAddress> dns = lp.getDnsServers();
                    if (dns != null)
                        for (InetAddress d : dns) {
                            Log.i(TAG, "DNS from LP: " + d.getHostAddress());
                            listDns.add(d.getHostAddress().split("%")[0]);
                        }
                }
            }
        } else {
            String dns1 = jni_getprop("net.dns1");
            String dns2 = jni_getprop("net.dns2");
            if (dns1 != null)
                listDns.add(dns1.split("%")[0]);
            if (dns2 != null)
                listDns.add(dns2.split("%")[0]);
        }

        return listDns;
    }

    public static boolean isNumericAddress(String ip) {
        return is_numeric_address(ip);
    }

    public static boolean isInteractive(Context context) {
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT_WATCH)
            return (pm != null && pm.isScreenOn());
        else
            return (pm != null && pm.isInteractive());
    }

    public static boolean isPackageInstalled(String packageName, Context context) {
        try {
            context.getPackageManager().getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    public static boolean isSystem(int uid, Context context) {
        PackageManager pm = context.getPackageManager();
        String[] pkgs = pm.getPackagesForUid(uid);
        if (pkgs != null)
            for (String pkg : pkgs)
                if (isSystem(pkg, context))
                    return true;
        return false;
    }

    public static boolean isSystem(String packageName, Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo info = pm.getPackageInfo(packageName, 0);
            return ((info.applicationInfo.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0);
            /*
            PackageInfo pkg = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
            PackageInfo sys = pm.getPackageInfo("android", PackageManager.GET_SIGNATURES);
            return (pkg != null && pkg.signatures != null && pkg.signatures.length > 0 &&
                    sys.signatures.length > 0 && sys.signatures[0].equals(pkg.signatures[0]));
            */
        } catch (PackageManager.NameNotFoundException ignore) {
            return false;
        }
    }

    public static boolean hasInternet(String packageName, Context context) {
        PackageManager pm = context.getPackageManager();
        return (pm.checkPermission("android.permission.INTERNET", packageName) == PackageManager.PERMISSION_GRANTED);
    }

    public static boolean hasInternet(int uid, Context context) {
        PackageManager pm = context.getPackageManager();
        String[] pkgs = pm.getPackagesForUid(uid);
        if (pkgs != null)
            for (String pkg : pkgs)
                if (hasInternet(pkg, context))
                    return true;
        return false;
    }

    public static boolean isEnabled(PackageInfo info, Context context) {
        int setting;
        try {
            PackageManager pm = context.getPackageManager();
            setting = pm.getApplicationEnabledSetting(info.packageName);
        } catch (IllegalArgumentException ex) {
            setting = PackageManager.COMPONENT_ENABLED_STATE_DEFAULT;
            Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
        if (setting == PackageManager.COMPONENT_ENABLED_STATE_DEFAULT)
            return info.applicationInfo.enabled;
        else
            return (setting == PackageManager.COMPONENT_ENABLED_STATE_ENABLED);
    }

    public static List<String> getApplicationNames(int uid, Context context) {
        List<String> listResult = new ArrayList<>();
        if (uid == 0)
            listResult.add(context.getString(R.string.title_root));
        else if (uid == 1013)
            listResult.add(context.getString(R.string.title_mediaserver));
        else if (uid == 9999)
            listResult.add(context.getString(R.string.title_nobody));
        else {
            PackageManager pm = context.getPackageManager();
            String[] pkgs = pm.getPackagesForUid(uid);
            if (pkgs != null)
                for (String pkg : pkgs)
                    try {
                        ApplicationInfo info = pm.getApplicationInfo(pkg, 0);
                        String name = pm.getApplicationLabel(info).toString();
                        listResult.add(TextUtils.isEmpty(name) ? pkg : name);
                    } catch (PackageManager.NameNotFoundException ignored) {
                    }
            Collections.sort(listResult);
        }
        return listResult;
    }

    public static boolean canFilter(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
            return true;

        // https://android-review.googlesource.com/#/c/206710/1/untrusted_app.te
        File tcp = new File("/proc/net/tcp");
        File tcp6 = new File("/proc/net/tcp6");
        try {
            if (tcp.exists() && tcp.canRead())
                return true;
        } catch (SecurityException ignored) {
        }
        try {
            return (tcp6.exists() && tcp6.canRead());
        } catch (SecurityException ignored) {
            return false;
        }
    }

    public static boolean isDebuggable(Context context) {
        return ((context.getApplicationContext().getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
    }

    public static boolean isPlayStoreInstall(Context context) {
        if (BuildConfig.PLAY_STORE_RELEASE)
            return true;
        try {
            return "com.android.vending".equals(context.getPackageManager().getInstallerPackageName(context.getPackageName()));
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            return false;
        }
    }

    public static boolean hasXposed(Context context) {
        if (true || !isPlayStoreInstall(context))
            return false;
        for (StackTraceElement ste : Thread.currentThread().getStackTrace())
            if (ste.getClassName().startsWith("de.robv.android.xposed"))
                return true;
        return false;
    }

    public static boolean ownFault(Context context, Throwable ex) {
        if (ex instanceof OutOfMemoryError)
            return false;
        if (ex.getCause() != null)
            ex = ex.getCause();
        for (StackTraceElement ste : ex.getStackTrace())
            if (ste.getClassName().startsWith(context.getPackageName()))
                return true;
        return false;
    }

    public static String getFingerprint(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            String pkg = context.getPackageName();
            PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
            byte[] cert = info.signatures[0].toByteArray();
            MessageDigest digest = MessageDigest.getInstance("SHA1");
            byte[] bytes = digest.digest(cert);
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes)
                sb.append(Integer.toString(b & 0xff, 16).toLowerCase());
            return sb.toString();
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            return null;
        }
    }

    public static boolean hasValidFingerprint(Context context) {
        String calculated = getFingerprint(context);
        String expected = context.getString(R.string.fingerprint);
        return (calculated != null && calculated.equals(expected));
    }

    public static void setTheme(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean dark = prefs.getBoolean("dark_theme", false);
        String theme = prefs.getString("theme", "teal");
        if (theme.equals("teal"))
            context.setTheme(dark ? R.style.AppThemeTealDark : R.style.AppThemeTeal);
        else if (theme.equals("blue"))
            context.setTheme(dark ? R.style.AppThemeBlueDark : R.style.AppThemeBlue);
        else if (theme.equals("purple"))
            context.setTheme(dark ? R.style.AppThemePurpleDark : R.style.AppThemePurple);
        else if (theme.equals("amber"))
            context.setTheme(dark ? R.style.AppThemeAmberDark : R.style.AppThemeAmber);
        else if (theme.equals("orange"))
            context.setTheme(dark ? R.style.AppThemeOrangeDark : R.style.AppThemeOrange);
        else if (theme.equals("green"))
            context.setTheme(dark ? R.style.AppThemeGreenDark : R.style.AppThemeGreen);

        if (context instanceof Activity && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            setTaskColor(context);
    }

    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    private static void setTaskColor(Context context) {
        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.colorPrimary, tv, true);
        ((Activity) context).setTaskDescription(new ActivityManager.TaskDescription(null, null, tv.data));
    }

    public static int dips2pixels(int dips, Context context) {
        return Math.round(dips * context.getResources().getDisplayMetrics().density + 0.5f);
    }

    private static int calculateInSampleSize(
            BitmapFactory.Options options, int reqWidth, int reqHeight) {
        int height = options.outHeight;
        int width = options.outWidth;
        int inSampleSize = 1;

        if (height > reqHeight || width > reqWidth) {
            int halfHeight = height / 2;
            int halfWidth = width / 2;

            while (halfHeight / inSampleSize >= reqHeight && halfWidth / inSampleSize >= reqWidth)
                inSampleSize *= 2;
        }

        return inSampleSize;
    }

    public static Bitmap decodeSampledBitmapFromResource(
            Resources resources, int resourceId, int reqWidth, int reqHeight) {

        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inJustDecodeBounds = true;
        BitmapFactory.decodeResource(resources, resourceId, options);
        options.inSampleSize = calculateInSampleSize(options, reqWidth, reqHeight);
        options.inJustDecodeBounds = false;

        return BitmapFactory.decodeResource(resources, resourceId, options);
    }

    public static String getProtocolName(int protocol, int version, boolean brief) {
        // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        String p = null;
        String b = null;
        switch (protocol) {
            case 0:
                p = "HOPO";
                b = "H";
                break;
            case 2:
                p = "IGMP";
                b = "G";
                break;
            case 1:
            case 58:
                p = "ICMP";
                b = "I";
                break;
            case 6:
                p = "TCP";
                b = "T";
                break;
            case 17:
                p = "UDP";
                b = "U";
                break;
            case 50:
                p = "ESP";
                b = "E";
                break;
        }
        if (p == null)
            return Integer.toString(protocol) + "/" + version;
        return ((brief ? b : p) + (version > 0 ? version : ""));
    }

    public interface DoubtListener {
        void onSure();
    }

    public static void areYouSure(Context context, int explanation, final DoubtListener listener) {
        LayoutInflater inflater = LayoutInflater.from(context);
        View view = inflater.inflate(R.layout.sure, null, false);
        TextView tvExplanation = view.findViewById(R.id.tvExplanation);
        tvExplanation.setText(explanation);
        new AlertDialog.Builder(context)
                .setView(view)
                .setCancelable(true)
                .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        listener.onSure();
                    }
                })
                .setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        // Do nothing
                    }
                })
                .create().show();
    }

    private static final Map<String, String> mapIPOrganization = new HashMap<>();

    public static String getOrganization(String ip) throws Exception {
        synchronized (mapIPOrganization) {
            if (mapIPOrganization.containsKey(ip))
                return mapIPOrganization.get(ip);
        }
        BufferedReader reader = null;
        try {
            URL url = new URL("https://ipinfo.io/" + ip + "/org");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setReadTimeout(15 * 1000);
            connection.connect();
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String organization = reader.readLine();
            if ("undefined".equals(organization))
                organization = null;
            synchronized (mapIPOrganization) {
                mapIPOrganization.put(ip, organization);
            }
            return organization;
        } finally {
            if (reader != null)
                reader.close();
        }
    }

    public static String md5(String text, String salt) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        // MD5
        byte[] bytes = MessageDigest.getInstance("MD5").digest((text + salt).getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02X", b));
        return sb.toString();
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

    public static StringBuilder readString(InputStreamReader reader) {
        StringBuilder sb = new StringBuilder(2048);
        char[] read = new char[128];
        try {
            for (int i; (i = reader.read(read)) >= 0; sb.append(read, 0, i)) ;
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
        return sb;
    }

    public static void sendCrashReport(Throwable ex, final Context context) {
        if (!isPlayStoreInstall(context) || Util.isDebuggable(context))
            return;

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
        sb.append(String.format("Connected %B\r\n", isConnected(context)));
        sb.append(String.format("WiFi %B\r\n", isWifiActive(context)));
        sb.append(String.format("Metered %B\r\n", isMeteredNetwork(context)));
        sb.append(String.format("Roaming %B\r\n", isRoaming(context)));

        if (tm.getSimState() == TelephonyManager.SIM_STATE_READY)
            sb.append(String.format("SIM %s/%s/%s\r\n", tm.getSimCountryIso(), tm.getSimOperatorName(), tm.getSimOperator()));
        //if (tm.getNetworkType() != TelephonyManager.NETWORK_TYPE_UNKNOWN)
        try {
            sb.append(String.format("Network %s/%s/%s\r\n", tm.getNetworkCountryIso(), tm.getNetworkOperatorName(), tm.getNetworkOperator()));
        } catch (Throwable ex) {
            /*
                06-14 13:02:41.331 19703 19703 W ircode.netguar: Accessing hidden method Landroid/view/View;->computeFitSystemWindows(Landroid/graphics/Rect;Landroid/graphics/Rect;)Z (greylist, reflection, allowed)
                06-14 13:02:41.332 19703 19703 W ircode.netguar: Accessing hidden method Landroid/view/ViewGroup;->makeOptionalFitsSystemWindows()V (greylist, reflection, allowed)
                06-14 13:02:41.495 19703 19703 I TetheringManager: registerTetheringEventCallback:eu.faircode.netguard
                06-14 13:02:41.518 19703 19703 E AndroidRuntime: Process: eu.faircode.netguard, PID: 19703
                06-14 13:02:41.518 19703 19703 E AndroidRuntime:        at eu.faircode.netguard.Util.getGeneralInfo(SourceFile:744)
                06-14 13:02:41.518 19703 19703 E AndroidRuntime:        at eu.faircode.netguard.ActivitySettings.updateTechnicalInfo(SourceFile:858)
                06-14 13:02:41.518 19703 19703 E AndroidRuntime:        at eu.faircode.netguard.ActivitySettings.onPostCreate(SourceFile:425)
                06-14 13:02:41.520 19703 19703 W NetGuard.App: java.lang.SecurityException: getDataNetworkTypeForSubscriber
                06-14 13:02:41.520 19703 19703 W NetGuard.App: java.lang.SecurityException: getDataNetworkTypeForSubscriber
                06-14 13:02:41.520 19703 19703 W NetGuard.App:  at android.os.Parcel.createExceptionOrNull(Parcel.java:2373)
                06-14 13:02:41.520 19703 19703 W NetGuard.App:  at android.os.Parcel.createException(Parcel.java:2357)
                06-14 13:02:41.520 19703 19703 W NetGuard.App:  at android.os.Parcel.readException(Parcel.java:2340)
                06-14 13:02:41.520 19703 19703 W NetGuard.App:  at android.os.Parcel.readException(Parcel.java:2282)
                06-14 13:02:41.520 19703 19703 W NetGuard.App:  at com.android.internal.telephony.ITelephony$Stub$Proxy.getNetworkTypeForSubscriber(ITelephony.java:8711)
                06-14 13:02:41.520 19703 19703 W NetGuard.App:  at android.telephony.TelephonyManager.getNetworkType(TelephonyManager.java:2945)
                06-14 13:02:41.520 19703 19703 W NetGuard.App:  at android.telephony.TelephonyManager.getNetworkType(TelephonyManager.java:2909)
             */
        }

        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP)
            sb.append(String.format("Power saving %B\r\n", pm.isPowerSaveMode()));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            sb.append(String.format("Battery optimizing %B\r\n", batteryOptimizing(context)));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            sb.append(String.format("Data saving %B\r\n", dataSaving(context)));

        if (sb.length() > 2)
            sb.setLength(sb.length() - 2);

        return sb.toString();
    }

    public static String getNetworkInfo(Context context) {
        StringBuilder sb = new StringBuilder();
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);

        NetworkInfo ani = cm.getActiveNetworkInfo();
        List<NetworkInfo> listNI = new ArrayList<>();

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP)
            listNI.addAll(Arrays.asList(cm.getAllNetworkInfo()));
        else
            for (Network network : cm.getAllNetworks()) {
                NetworkInfo ni = cm.getNetworkInfo(network);
                if (ni != null)
                    listNI.add(ni);
            }

        for (NetworkInfo ni : listNI) {
            sb.append(ni.getTypeName()).append('/').append(ni.getSubtypeName())
                    .append(' ').append(ni.getDetailedState())
                    .append(TextUtils.isEmpty(ni.getExtraInfo()) ? "" : " " + ni.getExtraInfo())
                    .append(ni.getType() == ConnectivityManager.TYPE_MOBILE ? " " + Util.getNetworkGeneration(ni.getSubtype()) : "")
                    .append(ni.isRoaming() ? " R" : "")
                    .append(ani != null && ni.getType() == ani.getType() && ni.getSubtype() == ani.getSubtype() ? " *" : "")
                    .append("\r\n");
        }

        try {
            Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            if (nis != null)
                while (nis.hasMoreElements()) {
                    NetworkInterface ni = nis.nextElement();
                    if (ni != null && !ni.isLoopback()) {
                        List<InterfaceAddress> ias = ni.getInterfaceAddresses();
                        if (ias != null)
                            for (InterfaceAddress ia : ias)
                                sb.append(ni.getName())
                                        .append(' ').append(ia.getAddress().getHostAddress())
                                        .append('/').append(ia.getNetworkPrefixLength())
                                        .append(' ').append(ni.getMTU())
                                        .append(' ').append(ni.isUp() ? '^' : 'v')
                                        .append("\r\n");
                    }
                }
        } catch (Throwable ex) {
            sb.append(ex.toString()).append("\r\n");
        }

        if (sb.length() > 2)
            sb.setLength(sb.length() - 2);

        return sb.toString();
    }

    @TargetApi(Build.VERSION_CODES.M)
    public static boolean batteryOptimizing(Context context) {
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        return !pm.isIgnoringBatteryOptimizations(context.getPackageName());
    }

    @TargetApi(Build.VERSION_CODES.N)
    public static boolean dataSaving(Context context) {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        return (cm.getRestrictBackgroundStatus() == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED);
    }

    public static boolean canNotify(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU)
            return true;
        else
            return (ActivityCompat.checkSelfPermission(context,
                    Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED);
    }

    private static StringBuilder getTrafficLog(Context context) {
        StringBuilder sb = new StringBuilder();

        try (Cursor cursor = DatabaseHelper.getInstance(context).getLog(true, true, true, true, true)) {

            int colTime = cursor.getColumnIndex("time");
            int colVersion = cursor.getColumnIndex("version");
            int colProtocol = cursor.getColumnIndex("protocol");
            int colFlags = cursor.getColumnIndex("flags");
            int colSAddr = cursor.getColumnIndex("saddr");
            int colSPort = cursor.getColumnIndex("sport");
            int colDAddr = cursor.getColumnIndex("daddr");
            int colDPort = cursor.getColumnIndex("dport");
            int colDName = cursor.getColumnIndex("dname");
            int colUid = cursor.getColumnIndex("uid");
            int colData = cursor.getColumnIndex("data");
            int colAllowed = cursor.getColumnIndex("allowed");
            int colConnection = cursor.getColumnIndex("connection");
            int colInteractive = cursor.getColumnIndex("interactive");

            DateFormat format = SimpleDateFormat.getDateTimeInstance();

            int count = 0;
            while (cursor.moveToNext() && ++count < 250) {
                sb.append(format.format(cursor.getLong(colTime)));
                sb.append(" v").append(cursor.getInt(colVersion));
                sb.append(" p").append(cursor.getInt(colProtocol));
                sb.append(' ').append(cursor.getString(colFlags));
                sb.append(' ').append(cursor.getString(colSAddr));
                sb.append('/').append(cursor.getInt(colSPort));
                sb.append(" > ").append(cursor.getString(colDAddr));
                sb.append('/').append(cursor.getString(colDName));
                sb.append('/').append(cursor.getInt(colDPort));
                sb.append(" u").append(cursor.getInt(colUid));
                sb.append(" a").append(cursor.getInt(colAllowed));
                sb.append(" c").append(cursor.getInt(colConnection));
                sb.append(" i").append(cursor.getInt(colInteractive));
                sb.append(' ').append(cursor.getString(colData));
                sb.append("\r\n");
            }
        }

        return sb;
    }
}
