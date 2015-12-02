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
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkInfo;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.preference.Preference;
import android.preference.PreferenceCategory;
import android.preference.PreferenceManager;
import android.preference.PreferenceScreen;
import android.preference.SwitchPreference;
import android.support.v7.app.AppCompatActivity;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Log;
import android.util.Xml;
import android.widget.Toast;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

public class ActivitySettings extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Settings";

    private boolean phone_state = false;
    private Preference pref_technical = null;

    private static final int REQUEST_EXPORT = 1;
    private static final int REQUEST_IMPORT = 2;
    private static final int REQUEST_READ_PHONE_STATE = 3;
    private static final Intent INTENT_VPN_SETTINGS = new Intent("android.net.vpn.SETTINGS");

    protected void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        setTheme(prefs.getBoolean("dark_theme", false) ? R.style.AppThemeDark : R.style.AppTheme);

        super.onCreate(savedInstanceState);

        refreshScreen();
        getSupportActionBar().setTitle(R.string.menu_settings);
    }

    private void refreshScreen() {
        getFragmentManager().beginTransaction().replace(android.R.id.content, new FragmentSettings()).commit();
    }

    @Override
    protected void onResume() {
        super.onResume();

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Check if permission was revoked
        if (prefs.getBoolean("national_roaming", false) && !Util.hasPhoneStatePermission(this)) {
            prefs.edit().putBoolean("national_roaming", false).apply();
            refreshScreen();
        }

        // Listen for preference changes
        prefs.registerOnSharedPreferenceChangeListener(this);

        // Listen for interactive state changes
        IntentFilter ifInteractive = new IntentFilter();
        ifInteractive.addAction(Intent.ACTION_SCREEN_ON);
        ifInteractive.addAction(Intent.ACTION_SCREEN_OFF);
        registerReceiver(interactiveStateReceiver, ifInteractive);

        // Listen for connectivity updates
        IntentFilter ifConnectivity = new IntentFilter();
        ifConnectivity.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, ifConnectivity);

        if (Util.hasPhoneStatePermission(this)) {
            TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
            tm.listen(phoneStateListener, PhoneStateListener.LISTEN_SERVICE_STATE);
            phone_state = true;
        }
    }

    @Override
    protected void onPause() {
        super.onPause();

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.unregisterOnSharedPreferenceChangeListener(this);

        unregisterReceiver(interactiveStateReceiver);
        unregisterReceiver(connectivityChangedReceiver);

        if (phone_state) {
            TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
            tm.listen(phoneStateListener, PhoneStateListener.LISTEN_NONE);
            phone_state = false;
        }
    }

    public void setup(PreferenceScreen screen) {
        Preference pref_export = screen.findPreference("export");
        pref_export.setEnabled(getIntentCreateDocument().resolveActivity(getPackageManager()) != null);
        pref_export.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                startActivityForResult(getIntentCreateDocument(), ActivitySettings.REQUEST_EXPORT);
                return true;
            }
        });

        Preference pref_import = screen.findPreference("import");
        pref_import.setEnabled(getIntentCreateDocument().resolveActivity(getPackageManager()) != null);
        pref_import.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                startActivityForResult(getIntentOpenDocument(), ActivitySettings.REQUEST_IMPORT);
                return true;
            }
        });

        pref_technical = screen.findPreference("technical");
        if (Util.isDebuggable(this)) {
            pref_technical.setEnabled(INTENT_VPN_SETTINGS.resolveActivity(this.getPackageManager()) != null);
            pref_technical.setIntent(INTENT_VPN_SETTINGS);
        }
        pref_technical.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                updateTechnicalInfo();
                return true;
            }
        });
        updateTechnicalInfo();

        if (!Util.hasTelephony(this)) {
            PreferenceCategory defaults = (PreferenceCategory) screen.findPreference("category_defaults");
            defaults.removePreference(screen.findPreference("whitelist_other"));
            defaults.removePreference(screen.findPreference("screen_other"));
            defaults.removePreference(screen.findPreference("whitelist_roaming"));

            PreferenceCategory options = (PreferenceCategory) screen.findPreference("category_options");
            options.removePreference(screen.findPreference("use_metered"));
            options.removePreference(screen.findPreference("national_roaming"));
        }
    }

    @Override
    @TargetApi(Build.VERSION_CODES.M)
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        if ("whitelist_wifi".equals(name) ||
                "screen_wifi".equals(name))
            SinkholeService.reload("wifi", this);

        else if ("whitelist_other".equals(name) ||
                "screen_other".equals(name) ||
                "whitelist_roaming".equals(name))
            SinkholeService.reload("other", this);

        else if ("national_roaming".equals(name)) {
            if (prefs.getBoolean(name, false)) {
                if (Util.hasPhoneStatePermission(this))
                    SinkholeService.reload("other", this);
                else
                    requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_READ_PHONE_STATE);
            } else
                SinkholeService.reload("other", this);

        } else if ("use_metered".equals(name) ||
                "manage_system".equals(name))
            SinkholeService.reload(null, this);

        else if ("dark_theme".equals(name))
            recreate();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == REQUEST_READ_PHONE_STATE)
            if (grantResults[0] == PackageManager.PERMISSION_GRANTED)
                SinkholeService.reload("other", this);
            else {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
                prefs.edit().putBoolean("national_roaming", false).apply();
                refreshScreen();
            }
    }

    private BroadcastReceiver interactiveStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Util.logExtras(intent);
            updateTechnicalInfo();
        }
    };

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Util.logExtras(intent);
            updateTechnicalInfo();
        }
    };

    private PhoneStateListener phoneStateListener = new PhoneStateListener() {
        @Override
        public void onServiceStateChanged(ServiceState serviceState) {
            super.onServiceStateChanged(serviceState);
            updateTechnicalInfo();
        }
    };

    private void updateTechnicalInfo() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Interactive %B\r\n", Util.isInteractive(this)));
        sb.append(String.format("Telephony %B\r\n", Util.hasTelephony(this)));
        sb.append(String.format("Connected %B\r\n", Util.isConnected(this)));
        sb.append(String.format("WiFi %B\r\n", Util.isWifiActive(this)));
        sb.append(String.format("Metered %B\r\n", Util.isMeteredNetwork(this)));
        sb.append(String.format("Roaming %B\r\n", Util.isRoaming(this)));

        if (tm.getSimState() == TelephonyManager.SIM_STATE_READY)
            sb.append(String.format("SIM %s/%s/%s\r\n", tm.getSimCountryIso(), tm.getSimOperatorName(), tm.getSimOperator()));
        if (tm.getNetworkType() != TelephonyManager.NETWORK_TYPE_UNKNOWN)
            sb.append(String.format("Network %s/%s/%s\r\n", tm.getNetworkCountryIso(), tm.getNetworkOperatorName(), tm.getNetworkOperator()));

        for (Network network : cm.getAllNetworks()) {
            NetworkInfo ni = cm.getNetworkInfo(network);
            if (ni != null)
                sb.append(ni.getTypeName())
                        .append("/")
                        .append(ni.getSubtypeName())
                        .append(" ").append(ni.getDetailedState())
                        .append(TextUtils.isEmpty(ni.getExtraInfo()) ? "" : " " + ni.getExtraInfo())
                        .append(ni.getType() == ConnectivityManager.TYPE_MOBILE ? " " + getNetworkGeneration(ni.getSubtype()) : "")
                        .append(ni.isRoaming() ? " R" : "")
                        .append("\r\n");
        }

        pref_technical.setSummary(sb.toString());
    }

    private static String getNetworkGeneration(int networkType) {
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
                return "3G";

            case TelephonyManager.NETWORK_TYPE_LTE:
                return "4G";

            default:
                return "?G";
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, final Intent data) {
        Log.i(TAG, "onActivityResult request=" + requestCode + " result=" + requestCode + " ok=" + (resultCode == RESULT_OK));
        if (requestCode == REQUEST_EXPORT) {
            if (resultCode == RESULT_OK && data != null)
                handleExport(data);

        } else if (requestCode == REQUEST_IMPORT) {
            if (resultCode == RESULT_OK && data != null)
                handleImport(data);

        } else {
            Log.w(TAG, "Unknown activity result request=" + requestCode);
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    private void handleExport(final Intent data) {
        new AsyncTask<Object, Object, Throwable>() {
            @Override
            protected Throwable doInBackground(Object... objects) {
                OutputStream out = null;
                try {
                    out = getContentResolver().openOutputStream(data.getData());
                    Log.i(TAG, "Writing URI=" + data.getData());
                    xmlExport(out);
                    return null;
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    Util.sendCrashReport(ex, ActivitySettings.this);
                    return ex;
                } finally {
                    if (out != null)
                        try {
                            out.close();
                        } catch (IOException ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
                }
            }

            @Override
            protected void onPostExecute(Throwable ex) {
                if (ex == null)
                    Toast.makeText(ActivitySettings.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                else
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
        }.execute();
    }

    private static Intent getIntentCreateDocument() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/xml");
        intent.putExtra(Intent.EXTRA_TITLE, "netguard.xml");
        return intent;
    }

    private static Intent getIntentOpenDocument() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("text/xml");
        return intent;
    }

    private void handleImport(final Intent data) {
        new AsyncTask<Object, Object, Throwable>() {
            @Override
            protected Throwable doInBackground(Object... objects) {
                InputStream in = null;
                try {
                    in = getContentResolver().openInputStream(data.getData());
                    Log.i(TAG, "Reading URI=" + data.getData());
                    xmlImport(in);
                    return null;
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    Util.sendCrashReport(ex, ActivitySettings.this);
                    return ex;
                } finally {
                    if (in != null)
                        try {
                            in.close();
                        } catch (IOException ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
                }
            }

            @Override
            protected void onPostExecute(Throwable ex) {
                if (ex == null) {
                    refreshScreen();
                    Toast.makeText(ActivitySettings.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                } else
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
        }.execute();
    }

    private void xmlExport(OutputStream out) throws IOException {
        XmlSerializer serializer = Xml.newSerializer();
        serializer.setOutput(out, "UTF-8");
        serializer.startDocument(null, true);
        serializer.setFeature("http://xmlpull.org/v1/doc/features.html#indent-output", true);
        serializer.startTag(null, "netguard");

        serializer.startTag(null, "application");
        xmlExport(PreferenceManager.getDefaultSharedPreferences(this), serializer);
        serializer.endTag(null, "application");

        serializer.startTag(null, "wifi");
        xmlExport(getSharedPreferences("wifi", Context.MODE_PRIVATE), serializer);
        serializer.endTag(null, "wifi");

        serializer.startTag(null, "mobile");
        xmlExport(getSharedPreferences("other", Context.MODE_PRIVATE), serializer);
        serializer.endTag(null, "mobile");

        serializer.startTag(null, "screen_wifi");
        xmlExport(getSharedPreferences("screen_wifi", Context.MODE_PRIVATE), serializer);
        serializer.endTag(null, "screen_wifi");

        serializer.startTag(null, "screen_other");
        xmlExport(getSharedPreferences("screen_other", Context.MODE_PRIVATE), serializer);
        serializer.endTag(null, "screen_other");

        serializer.endTag(null, "netguard");
        serializer.endDocument();
        serializer.flush();
    }

    private void xmlExport(SharedPreferences prefs, XmlSerializer serializer) throws IOException {
        Map<String, ?> settings = prefs.getAll();
        for (String key : settings.keySet()) {
            Object value = settings.get(key);

            if ("imported".equals(key))
                continue;

            if (value instanceof Boolean) {
                serializer.startTag(null, "setting");
                serializer.attribute(null, "key", key);
                serializer.attribute(null, "type", "boolean");
                serializer.attribute(null, "value", value.toString());
                serializer.endTag(null, "setting");

            } else if (value instanceof Integer) {
                serializer.startTag(null, "setting");
                serializer.attribute(null, "key", key);
                serializer.attribute(null, "type", "integer");
                serializer.attribute(null, "value", value.toString());
                serializer.endTag(null, "setting");

            } else
                Log.e(TAG, "Unknown key=" + key);
        }
    }

    private void xmlImport(InputStream in) throws IOException, SAXException, ParserConfigurationException {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.edit().putBoolean("enabled", false).apply();
        SinkholeService.stop(this);

        XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
        XmlImportHandler handler = new XmlImportHandler();
        reader.setContentHandler(handler);
        reader.parse(new InputSource(in));

        xmlImport(handler.application, prefs);
        xmlImport(handler.wifi, getSharedPreferences("wifi", Context.MODE_PRIVATE));
        xmlImport(handler.mobile, getSharedPreferences("other", Context.MODE_PRIVATE));
        xmlImport(handler.unused, getSharedPreferences("unused", Context.MODE_PRIVATE));
        xmlImport(handler.screen_wifi, getSharedPreferences("screen_wifi", Context.MODE_PRIVATE));
        xmlImport(handler.screen_other, getSharedPreferences("screen_other", Context.MODE_PRIVATE));
        xmlImport(handler.roaming, getSharedPreferences("roaming", Context.MODE_PRIVATE));

        // Upgrade imported settings
        Receiver.upgrade(true, this);

        // Refresh UI
        prefs.edit().putBoolean("imported", true).apply();
    }

    private void xmlImport(Map<String, Object> settings, SharedPreferences prefs) {
        SharedPreferences.Editor editor = prefs.edit();

        // Clear existing setting
        for (String key : prefs.getAll().keySet())
            if (!"enabled".equals(key))
                editor.remove(key);

        // Apply new settings
        for (String key : settings.keySet()) {
            Object value = settings.get(key);
            if (value instanceof Boolean)
                editor.putBoolean(key, (Boolean) value);
            else if (value instanceof Integer)
                editor.putInt(key, (Integer) value);
            else
                Log.e(TAG, "Unknown type=" + value.getClass());
        }

        editor.apply();
    }

    private class XmlImportHandler extends DefaultHandler {
        public boolean enabled = false;
        public Map<String, Object> application = new HashMap<>();
        public Map<String, Object> wifi = new HashMap<>();
        public Map<String, Object> mobile = new HashMap<>();
        public Map<String, Object> unused = new HashMap<>();
        public Map<String, Object> screen_wifi = new HashMap<>();
        public Map<String, Object> screen_other = new HashMap<>();
        public Map<String, Object> roaming = new HashMap<>();
        private Map<String, Object> current = null;

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) {
            if (qName.equals("netguard"))
                ; // Ignore

            else if (qName.equals("application"))
                current = application;

            else if (qName.equals("wifi"))
                current = wifi;

            else if (qName.equals("mobile"))
                current = mobile;

            else if (qName.equals("unused"))
                current = unused;

            else if (qName.equals("screen_wifi"))
                current = screen_wifi;

            else if (qName.equals("screen_other"))
                current = screen_other;

            else if (qName.equals("roaming"))
                current = roaming;

            else if (qName.equals("setting")) {
                String key = attributes.getValue("key");
                String type = attributes.getValue("type");
                String value = attributes.getValue("value");

                if (current == null)
                    Log.e(TAG, "No current key=" + key);
                else {
                    if ("enabled".equals(key))
                        enabled = Boolean.parseBoolean(value);
                    else {
                        if ("boolean".equals(type))
                            current.put(key, Boolean.parseBoolean(value));
                        else if ("integer".equals(type))
                            current.put(key, Integer.parseInt(value));
                        else
                            Log.e(TAG, "Unknown type key=" + key);
                    }
                }

            } else
                Log.e(TAG, "Unknown element qname=" + qName);
        }
    }
}
