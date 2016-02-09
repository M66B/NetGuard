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

import android.Manifest;
import android.annotation.TargetApi;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.Uri;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.preference.EditTextPreference;
import android.preference.ListPreference;
import android.preference.MultiSelectListPreference;
import android.preference.Preference;
import android.preference.PreferenceCategory;
import android.preference.PreferenceFragment;
import android.preference.PreferenceManager;
import android.preference.PreferenceScreen;
import android.preference.TwoStatePreference;
import android.support.annotation.NonNull;
import android.support.v4.app.NavUtils;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.telephony.PhoneStateListener;
import android.telephony.ServiceState;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.util.Log;
import android.util.Xml;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xmlpull.v1.XmlSerializer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

public class ActivitySettings extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Settings";

    private boolean running = false;
    private boolean phone_state = false;

    private static final int REQUEST_EXPORT = 1;
    private static final int REQUEST_IMPORT = 2;
    private static final int REQUEST_METERED2 = 3;
    private static final int REQUEST_METERED3 = 4;
    private static final int REQUEST_METERED4 = 5;
    private static final int REQUEST_ROAMING_NATIONAL = 6;
    private static final int REQUEST_ROAMING_INTERNATIONAL = 7;
    private static final int REQUEST_HOSTS = 8;

    private AlertDialog dialogFilter = null;

    private static final Intent INTENT_VPN_SETTINGS = new Intent("android.net.vpn.SETTINGS");

    protected void onCreate(Bundle savedInstanceState) {
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        getFragmentManager().beginTransaction().replace(android.R.id.content, new FragmentSettings()).commit();
        getSupportActionBar().setTitle(R.string.menu_settings);
        running = true;
    }

    private PreferenceScreen getPreferenceScreen() {
        return ((PreferenceFragment) getFragmentManager().findFragmentById(android.R.id.content)).getPreferenceScreen();
    }

    @Override
    protected void onPostCreate(Bundle savedInstanceState) {
        super.onPostCreate(savedInstanceState);
        final PreferenceScreen screen = getPreferenceScreen();
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Handle auto enable
        Preference pref_auto_enable = screen.findPreference("auto_enable");
        pref_auto_enable.setTitle(getString(R.string.setting_auto, prefs.getString("auto_enable", "0")));

        // Handle screen delay
        Preference pref_screen_delay = screen.findPreference("screen_delay");
        pref_screen_delay.setTitle(getString(R.string.setting_delay, prefs.getString("screen_delay", "0")));

        // Handle theme
        Preference pref_screen_theme = screen.findPreference("theme");
        String theme = prefs.getString("theme", "teal");
        String[] themeNames = getResources().getStringArray(R.array.themeNames);
        String[] themeValues = getResources().getStringArray(R.array.themeValues);
        for (int i = 0; i < themeNames.length; i++)
            if (theme.equals(themeValues[i])) {
                pref_screen_theme.setTitle(getString(R.string.setting_theme, themeNames[i]));
                break;
            }

        // Wi-Fi home
        MultiSelectListPreference pref_wifi_homes = (MultiSelectListPreference) screen.findPreference("wifi_homes");
        Set<String> ssid = prefs.getStringSet("wifi_homes", new HashSet<String>());
        if (ssid.size() > 0)
            pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, TextUtils.join(", ", ssid)));
        else
            pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, "-"));

        WifiManager wm = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        List<CharSequence> listSSID = new ArrayList<>();
        List<WifiConfiguration> configs = wm.getConfiguredNetworks();
        if (configs != null)
            for (WifiConfiguration config : configs)
                listSSID.add(config.SSID == null ? "NULL" : config.SSID);
        pref_wifi_homes.setEntries(listSSID.toArray(new CharSequence[0]));
        pref_wifi_homes.setEntryValues(listSSID.toArray(new CharSequence[0]));

        // Filtering always enabled
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            PreferenceCategory options = (PreferenceCategory) screen.findPreference("category_advanced_options");
            options.removePreference(screen.findPreference("filter"));
        }

        // Handle port forwarding
        Preference pref_forwarding = screen.findPreference("forwarding");
        pref_forwarding.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                startActivity(new Intent(ActivitySettings.this, ActivityForwarding.class));
                return true;
            }
        });

        // VPN parameters
        screen.findPreference("vpn4").setTitle(getString(R.string.setting_vpn4, prefs.getString("vpn4", "10.1.10.1")));
        screen.findPreference("vpn6").setTitle(getString(R.string.setting_vpn6, prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1")));
        EditTextPreference pref_dns = (EditTextPreference) screen.findPreference("dns");
        String def_dns = Util.getDefaultDNS(this);
        pref_dns.getEditText().setHint(def_dns);
        pref_dns.setTitle(getString(R.string.setting_dns, prefs.getString("dns", def_dns)));

        // Handle stats
        EditTextPreference pref_stats_base = (EditTextPreference) screen.findPreference("stats_base");
        EditTextPreference pref_stats_frequency = (EditTextPreference) screen.findPreference("stats_frequency");
        EditTextPreference pref_stats_samples = (EditTextPreference) screen.findPreference("stats_samples");
        pref_stats_base.setTitle(getString(R.string.setting_stats_base, prefs.getString("stats_base", "5")));
        pref_stats_frequency.setTitle(getString(R.string.setting_stats_frequency, prefs.getString("stats_frequency", "1000")));
        pref_stats_samples.setTitle(getString(R.string.setting_stats_samples, prefs.getString("stats_samples", "90")));

        // Handle export
        Preference pref_export = screen.findPreference("export");
        pref_export.setEnabled(getIntentCreateExport().resolveActivity(getPackageManager()) != null);
        pref_export.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                startActivityForResult(getIntentCreateExport(), ActivitySettings.REQUEST_EXPORT);
                return true;
            }
        });

        // Handle import
        Preference pref_import = screen.findPreference("import");
        pref_import.setEnabled(getIntentOpenExport().resolveActivity(getPackageManager()) != null);
        pref_import.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                startActivityForResult(getIntentOpenExport(), ActivitySettings.REQUEST_IMPORT);
                return true;
            }
        });

        // Hosts file settings
        Preference pref_hosts = screen.findPreference("hosts");
        Preference pref_block_domains = screen.findPreference("use_hosts");
        EditTextPreference pref_hosts_url = (EditTextPreference) screen.findPreference("hosts_url");
        final Preference pref_hosts_download = screen.findPreference("hosts_download");
        String last = prefs.getString("hosts_last", null);
        if (last != null)
            pref_hosts_download.setSummary(getString(R.string.msg_download_last, last));

        if (Util.isPlayStoreInstall(this)) {
            PreferenceCategory pref_category = (PreferenceCategory) screen.findPreference("category_advanced_options");
            pref_category.removePreference(pref_block_domains);
            PreferenceCategory pref_backup = (PreferenceCategory) screen.findPreference("category_backup");
            pref_backup.removePreference(pref_hosts);
            pref_backup.removePreference(pref_hosts_url);
            pref_backup.removePreference(pref_hosts_download);

        } else {
            pref_block_domains.setEnabled(new File(getFilesDir(), "hosts.txt").exists());

            // Handle hosts import
            // https://github.com/Free-Software-for-Android/AdAway/wiki/HostsSources
            pref_hosts.setEnabled(getIntentOpenHosts().resolveActivity(getPackageManager()) != null);
            pref_hosts.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    startActivityForResult(getIntentOpenHosts(), ActivitySettings.REQUEST_HOSTS);
                    return true;
                }
            });

            // Handle hosts file download
            pref_hosts_url.setSummary(pref_hosts_url.getText());
            pref_hosts_download.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    final File tmp = new File(getFilesDir(), "hosts.tmp");
                    final File hosts = new File(getFilesDir(), "hosts.txt");
                    EditTextPreference pref_hosts_url = (EditTextPreference) screen.findPreference("hosts_url");
                    try {
                        new DownloadTask(ActivitySettings.this, new URL(pref_hosts_url.getText()), tmp, new DownloadTask.Listener() {
                            @Override
                            public void onCompleted() {
                                if (hosts.exists())
                                    hosts.delete();
                                tmp.renameTo(hosts);

                                String last = SimpleDateFormat.getDateTimeInstance().format(new Date().getTime());
                                prefs.edit().putString("hosts_last", last).apply();

                                if (running) {
                                    pref_hosts_download.setSummary(getString(R.string.msg_download_last, last));
                                    Toast.makeText(ActivitySettings.this, R.string.msg_downloaded, Toast.LENGTH_LONG).show();
                                }

                                SinkholeService.reload(null, "hosts file download", ActivitySettings.this);
                            }

                            @Override
                            public void onCancelled() {
                                if (tmp.exists())
                                    tmp.delete();
                            }

                            @Override
                            public void onException(Throwable ex) {
                                if (tmp.exists())
                                    tmp.delete();

                                if (running)
                                    Toast.makeText(ActivitySettings.this, ex.getMessage(), Toast.LENGTH_LONG).show();
                            }
                        }).execute();
                    } catch (MalformedURLException ex) {
                        Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
                    }
                    return true;
                }
            });
        }

        // Development
        if (!(Util.isDebuggable(this) || Util.getSelfVersionName(this).contains("beta"))) {
            screen.removePreference(screen.findPreference("category_development"));
            prefs.edit().remove("loglevel").apply();
        }

        // Handle technical info
        Preference.OnPreferenceClickListener listener = new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                updateTechnicalInfo();
                return true;
            }
        };

        // Technical info
        Preference pref_technical_info = screen.findPreference("technical_info");
        Preference pref_technical_network = screen.findPreference("technical_network");
        Preference pref_technical_subscription = screen.findPreference("technical_subscription");
        pref_technical_info.setEnabled(INTENT_VPN_SETTINGS.resolveActivity(this.getPackageManager()) != null);
        pref_technical_info.setIntent(INTENT_VPN_SETTINGS);
        pref_technical_info.setOnPreferenceClickListener(listener);
        pref_technical_network.setOnPreferenceClickListener(listener);
        pref_technical_subscription.setOnPreferenceClickListener(listener);
        updateTechnicalInfo();
    }

    @Override
    protected void onResume() {
        super.onResume();

        // Check if permissions were revoked
        checkPermissions();

        // Listen for preference changes
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
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
            tm.listen(phoneStateListener, PhoneStateListener.LISTEN_DATA_CONNECTION_STATE | PhoneStateListener.LISTEN_SERVICE_STATE);
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

    @Override
    protected void onDestroy() {
        running = false;
        if (dialogFilter != null) {
            dialogFilter.dismiss();
            dialogFilter = null;
        }
        super.onDestroy();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                Log.i(TAG, "Up");
                NavUtils.navigateUpFromSameTask(this);
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    @Override
    @TargetApi(Build.VERSION_CODES.M)
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        // Pro features
        if ("theme".equals(name)) {
            if (!"teal".equals(prefs.getString(name, "teal")) && !IAB.isPurchased(ActivityPro.SKU_THEME, this)) {
                prefs.edit().putString(name, "teal").apply();
                ((ListPreference) getPreferenceScreen().findPreference(name)).setValue("teal");
                startActivity(new Intent(this, ActivityPro.class));
                return;
            }
        } else if ("show_stats".equals(name)) {
            if (prefs.getBoolean(name, false) && !IAB.isPurchased(ActivityPro.SKU_SPEED, this)) {
                prefs.edit().putBoolean(name, false).apply();
                ((TwoStatePreference) getPreferenceScreen().findPreference(name)).setChecked(false);
                startActivity(new Intent(this, ActivityPro.class));
                return;
            }
        }

        // Dependencies
        if ("whitelist_wifi".equals(name) ||
                "screen_wifi".equals(name))
            SinkholeService.reload("wifi", "changed " + name, this);

        else if ("whitelist_other".equals(name) ||
                "screen_other".equals(name))
            SinkholeService.reload("other", "changed " + name, this);

        else if ("whitelist_roaming".equals(name)) {
            if (prefs.getBoolean(name, false)) {
                if (Util.hasPhoneStatePermission(this))
                    SinkholeService.reload("other", "changed " + name, this);
                else
                    requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_ROAMING_INTERNATIONAL);
            } else
                SinkholeService.reload("other", "changed " + name, this);

        } else if ("auto_enable".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_auto, prefs.getString(name, "0")));

        else if ("screen_delay".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_delay, prefs.getString(name, "0")));

        else if ("theme".equals(name) || "dark_theme".equals(name))
            recreate();

        else if ("tethering".equals(name))
            SinkholeService.reload(null, "changed " + name, this);

        else if ("wifi_homes".equals(name)) {
            MultiSelectListPreference pref_wifi_homes = (MultiSelectListPreference) getPreferenceScreen().findPreference(name);
            Set<String> ssid = prefs.getStringSet(name, new HashSet<String>());
            if (ssid.size() > 0)
                pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, TextUtils.join(", ", ssid)));
            else
                pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, "-"));
            SinkholeService.reload(null, "changed " + name, this);

        } else if ("use_metered".equals(name))
            SinkholeService.reload(null, "changed " + name, this);

        else if ("unmetered_2g".equals(name) ||
                "unmetered_3g".equals(name) ||
                "unmetered_4g".equals(name)) {
            if (prefs.getBoolean(name, false)) {
                if (Util.hasPhoneStatePermission(this))
                    SinkholeService.reload("other", "changed " + name, this);
                else {
                    if ("unmetered_2g".equals(name))
                        requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_METERED2);
                    else if ("unmetered_3g".equals(name))
                        requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_METERED3);
                    else if ("unmetered_4g".equals(name))
                        requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_METERED4);
                }
            } else
                SinkholeService.reload("other", "changed " + name, this);

        } else if ("national_roaming".equals(name)) {
            if (prefs.getBoolean(name, false)) {
                if (Util.hasPhoneStatePermission(this))
                    SinkholeService.reload("other", "changed " + name, this);
                else
                    requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_ROAMING_NATIONAL);
            } else
                SinkholeService.reload("other", "changed " + name, this);


        } else if ("manage_system".equals(name)) {
            boolean manage = prefs.getBoolean(name, false);
            if (!manage)
                prefs.edit().putBoolean("show_user", true).apply();
            prefs.edit().putBoolean("show_system", manage).apply();
            SinkholeService.reload(null, "changed " + name, this);

        } else if ("log_app".equals(name)) {
            Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
            LocalBroadcastManager.getInstance(this).sendBroadcast(ruleset);

        } else if ("filter".equals(name)) {
            SinkholeService.reload(null, "changed " + name, this);

            // Show dialog
            if (prefs.getBoolean(name, false)) {
                LayoutInflater inflater = LayoutInflater.from(ActivitySettings.this);
                View view = inflater.inflate(R.layout.filter, null);
                dialogFilter = new AlertDialog.Builder(ActivitySettings.this)
                        .setView(view)
                        .setCancelable(false)
                        .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                // Do nothing
                            }
                        })
                        .setOnDismissListener(new DialogInterface.OnDismissListener() {
                            @Override
                            public void onDismiss(DialogInterface dialogInterface) {
                                dialogFilter = null;
                            }
                        })
                        .create();
                dialogFilter.show();
            }

        } else if ("use_hosts".equals(name))
            SinkholeService.reload(null, "changed " + name, this);

        else if ("vpn4".equals(name)) {
            String vpn4 = prefs.getString("vpn4", null);
            try {
                if (vpn4 == null || TextUtils.isEmpty(vpn4.trim()))
                    throw new IllegalArgumentException("vpn4");
                InetAddress.getByName(vpn4);
                SinkholeService.reload(null, "changed " + name, this);
            } catch (Throwable ex) {
                Log.w(TAG, ex.toString());
                prefs.edit().remove("vpn4").apply();
            }
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_vpn4, prefs.getString("vpn4", "10.1.10.1")));

        } else if ("vpn6".equals(name)) {
            String vpn6 = prefs.getString("vpn6", null);
            try {
                if (vpn6 == null || TextUtils.isEmpty(vpn6.trim()))
                    throw new IllegalArgumentException("vpn6");
                InetAddress.getByName(vpn6);
                SinkholeService.reload(null, "changed " + name, this);
            } catch (Throwable ex) {
                Log.w(TAG, ex.toString());
                prefs.edit().remove("vpn6").apply();
            }
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_vpn6, prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1")));

        } else if ("dns".equals(name)) {
            String dns = prefs.getString("dns", null);
            try {
                if (dns == null || TextUtils.isEmpty(dns.trim()))
                    throw new IllegalArgumentException("dns");
                InetAddress.getByName(dns);
                SinkholeService.reload(null, "changed " + name, this);
            } catch (Throwable ex) {
                Log.w(TAG, ex.toString());
                prefs.edit().remove("dns").apply();
            }
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_dns, prefs.getString("dns", Util.getDefaultDNS(this))));

        } else if ("show_stats".equals(name))
            SinkholeService.reloadStats("changed " + name, this);

        else if ("stats_base".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_stats_base, prefs.getString(name, "5")));

        else if ("stats_frequency".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_stats_frequency, prefs.getString(name, "1000")));

        else if ("stats_samples".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_stats_samples, prefs.getString(name, "90")));

        else if ("hosts_url".equals(name))
            getPreferenceScreen().findPreference(name).setSummary(prefs.getString(name, "http://www.netguard.me/hosts"));

        else if ("loglevel".equals(name))
            SinkholeService.reload(null, "changed " + name, this);
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void checkPermissions() {
        PreferenceScreen screen = getPreferenceScreen();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Check if permission was revoked
        if (prefs.getBoolean("whitelist_roaming", false))
            if (!Util.hasPhoneStatePermission(this)) {
                prefs.edit().putBoolean("whitelist_roaming", false).apply();
                ((TwoStatePreference) screen.findPreference("whitelist_roaming")).setChecked(false);

                requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_ROAMING_INTERNATIONAL);
            }

        // Check if permission was revoked
        if (prefs.getBoolean("unmetered_2g", false))
            if (!Util.hasPhoneStatePermission(this)) {
                prefs.edit().putBoolean("unmetered_2g", false).apply();
                ((TwoStatePreference) screen.findPreference("unmetered_2g")).setChecked(false);

                requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_METERED2);
            }

        if (prefs.getBoolean("unmetered_3g", false))
            if (!Util.hasPhoneStatePermission(this)) {
                prefs.edit().putBoolean("unmetered_3g", false).apply();
                ((TwoStatePreference) screen.findPreference("unmetered_3g")).setChecked(false);

                requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_METERED3);
            }

        if (prefs.getBoolean("unmetered_4g", false))
            if (!Util.hasPhoneStatePermission(this)) {
                prefs.edit().putBoolean("unmetered_4g", false).apply();
                ((TwoStatePreference) screen.findPreference("unmetered_4g")).setChecked(false);

                requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_METERED4);
            }

        // Check if permission was revoked
        if (prefs.getBoolean("national_roaming", false))
            if (!Util.hasPhoneStatePermission(this)) {
                prefs.edit().putBoolean("national_roaming", false).apply();
                ((TwoStatePreference) screen.findPreference("national_roaming")).setChecked(false);

                requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_ROAMING_NATIONAL);
            }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        PreferenceScreen screen = getPreferenceScreen();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        boolean granted = (grantResults[0] == PackageManager.PERMISSION_GRANTED);

        if (requestCode == REQUEST_METERED2) {
            prefs.edit().putBoolean("unmetered_2g", granted).apply();
            ((TwoStatePreference) screen.findPreference("unmetered_2g")).setChecked(granted);

        } else if (requestCode == REQUEST_METERED3) {
            prefs.edit().putBoolean("unmetered_3g", granted).apply();
            ((TwoStatePreference) screen.findPreference("unmetered_3g")).setChecked(granted);

        } else if (requestCode == REQUEST_METERED4) {
            prefs.edit().putBoolean("unmetered_4g", granted).apply();
            ((TwoStatePreference) screen.findPreference("unmetered_4g")).setChecked(granted);

        } else if (requestCode == REQUEST_ROAMING_NATIONAL) {
            prefs.edit().putBoolean("national_roaming", granted).apply();
            ((TwoStatePreference) screen.findPreference("national_roaming")).setChecked(granted);

        } else if (requestCode == REQUEST_ROAMING_INTERNATIONAL) {
            prefs.edit().putBoolean("whitelist_roaming", granted).apply();
            ((TwoStatePreference) screen.findPreference("whitelist_roaming")).setChecked(granted);
        }

        if (granted)
            SinkholeService.reload("other", "permission granted", this);
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
        public void onDataConnectionStateChanged(int state) {
            updateTechnicalInfo();
        }

        @Override
        public void onServiceStateChanged(ServiceState serviceState) {
            updateTechnicalInfo();
        }
    };

    private void updateTechnicalInfo() {
        PreferenceScreen screen = getPreferenceScreen();
        Preference pref_technical_info = screen.findPreference("technical_info");
        Preference pref_technical_network = screen.findPreference("technical_network");
        Preference pref_technical_subscription = screen.findPreference("technical_subscription");

        pref_technical_info.setSummary(Util.getGeneralInfo(this));
        pref_technical_network.setSummary(Util.getNetworkInfo(this));
        pref_technical_subscription.setSummary(Util.getSubscriptionInfo(this));
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

        } else if (requestCode == REQUEST_HOSTS) {
            if (resultCode == RESULT_OK && data != null)
                handleHosts(data);

        } else {
            Log.w(TAG, "Unknown activity result request=" + requestCode);
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    private Intent getIntentCreateExport() {
        Intent intent;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            if (Util.isPackageInstalled("org.openintents.filemanager", this)) {
                intent = new Intent("org.openintents.action.PICK_DIRECTORY");
            } else {
                intent = new Intent(Intent.ACTION_VIEW);
                intent.setData(Uri.parse("https://play.google.com/store/apps/details?id=org.openintents.filemanager"));
            }
        } else {
            intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("*/*"); // text/xml
            intent.putExtra(Intent.EXTRA_TITLE, "netguard_" + new SimpleDateFormat("yyyyMMdd").format(new Date().getTime()) + ".xml");
        }
        return intent;
    }

    private Intent getIntentOpenExport() {
        Intent intent;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP)
            intent = new Intent(Intent.ACTION_GET_CONTENT);
        else
            intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*"); // text/xml
        return intent;
    }

    private Intent getIntentOpenHosts() {
        Intent intent;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP)
            intent = new Intent(Intent.ACTION_GET_CONTENT);
        else
            intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*"); // text/plain
        return intent;
    }

    // TODO translate uid to package name for notify.<uid> setting

    private void handleExport(final Intent data) {
        new AsyncTask<Object, Object, Throwable>() {
            @Override
            protected Throwable doInBackground(Object... objects) {
                OutputStream out = null;
                try {
                    Uri target = data.getData();
                    if (data.hasExtra("org.openintents.extra.DIR_PATH"))
                        target = Uri.parse(target + "/netguard_" + new SimpleDateFormat("yyyyMMdd").format(new Date().getTime()) + ".xml");
                    Log.i(TAG, "Writing URI=" + target);
                    out = getContentResolver().openOutputStream(target);
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
                if (running) {
                    if (ex == null)
                        Toast.makeText(ActivitySettings.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                    else
                        Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
                }
            }
        }.execute();
    }

    private void handleHosts(final Intent data) {
        new AsyncTask<Object, Object, Throwable>() {
            @Override
            protected Throwable doInBackground(Object... objects) {
                File hosts = new File(getFilesDir(), "hosts.txt");

                FileOutputStream out = null;
                InputStream in = null;
                try {
                    Log.i(TAG, "Reading URI=" + data.getData());
                    in = getContentResolver().openInputStream(data.getData());
                    out = new FileOutputStream(hosts);

                    int len;
                    long total = 0;
                    byte[] buf = new byte[4096];
                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                        total += len;
                    }
                    Log.i(TAG, "Copied bytes=" + total);

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
                if (running) {
                    if (ex == null) {
                        Toast.makeText(ActivitySettings.this, R.string.msg_completed, Toast.LENGTH_LONG).show();

                        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ActivitySettings.this);
                        prefs.edit().remove("hosts_last").apply();
                        getPreferenceScreen().findPreference("hosts_download").setSummary(null);

                        SinkholeService.reload(null, "hosts", ActivitySettings.this);
                        getPreferenceScreen().findPreference("use_hosts").setEnabled(true);
                    } else
                        Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
                }
            }
        }.execute();
    }

    private void handleImport(final Intent data) {
        new AsyncTask<Object, Object, Throwable>() {
            @Override
            protected Throwable doInBackground(Object... objects) {
                InputStream in = null;
                try {
                    Log.i(TAG, "Reading URI=" + data.getData());
                    in = getContentResolver().openInputStream(data.getData());
                    xmlImport(in);
                    return null;
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
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
                if (running) {
                    if (ex == null) {
                        Toast.makeText(ActivitySettings.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                        SinkholeService.reloadStats("import", ActivitySettings.this);
                        // Update theme, request permissions
                        recreate();
                    } else
                        Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
                }
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

        serializer.startTag(null, "filter");
        filterExport(serializer);
        serializer.endTag(null, "filter");

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

            } else if (value instanceof String) {
                serializer.startTag(null, "setting");
                serializer.attribute(null, "key", key);
                serializer.attribute(null, "type", "string");
                serializer.attribute(null, "value", value.toString());
                serializer.endTag(null, "setting");

            } else if (value instanceof Set) {
                Set<String> set = (Set<String>) value;
                serializer.startTag(null, "setting");
                serializer.attribute(null, "key", key);
                serializer.attribute(null, "type", "set");
                serializer.attribute(null, "value", TextUtils.join("\n", set));
                serializer.endTag(null, "setting");

            } else
                Log.e(TAG, "Unknown key=" + key);
        }
    }

    private void filterExport(XmlSerializer serializer) throws IOException {
        PackageManager pm = getPackageManager();
        DatabaseHelper dh = new DatabaseHelper(this);
        Cursor cursor = dh.getAccess();
        int colUid = cursor.getColumnIndex("uid");
        int colVersion = cursor.getColumnIndex("version");
        int colProtocol = cursor.getColumnIndex("protocol");
        int colDAddr = cursor.getColumnIndex("daddr");
        int colDPort = cursor.getColumnIndex("dport");
        int colTime = cursor.getColumnIndex("time");
        int colBlock = cursor.getColumnIndex("block");
        while (cursor.moveToNext()) {
            int uid = cursor.getInt(colUid);
            String pkgs[] = pm.getPackagesForUid(uid);
            if (pkgs == null) {
                Log.w(TAG, "No packages for uid=" + uid);
                continue;
            }
            for (String pkg : pkgs) {
                serializer.startTag(null, "rule");
                serializer.attribute(null, "pkg", pkg);
                serializer.attribute(null, "version", Integer.toString(cursor.getInt(colVersion)));
                serializer.attribute(null, "protocol", Integer.toString(cursor.getInt(colProtocol)));
                serializer.attribute(null, "daddr", cursor.getString(colDAddr));
                serializer.attribute(null, "dport", Integer.toString(cursor.getInt(colDPort)));
                serializer.attribute(null, "time", Long.toString(cursor.getLong(colTime)));
                serializer.attribute(null, "block", Integer.toString(cursor.getInt(colBlock)));
                serializer.endTag(null, "rule");
            }
        }
        cursor.close();
        dh.close();
    }

    private void xmlImport(InputStream in) throws IOException, SAXException, ParserConfigurationException {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.unregisterOnSharedPreferenceChangeListener(this);
        prefs.edit().putBoolean("enabled", false).apply();
        SinkholeService.stop("import", this);

        DatabaseHelper dh = new DatabaseHelper(this);
        dh.clearAccess();
        try {
            XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
            XmlImportHandler handler = new XmlImportHandler(this, dh);
            reader.setContentHandler(handler);
            reader.parse(new InputSource(in));

            xmlImport(handler.application, prefs);
            xmlImport(handler.wifi, getSharedPreferences("wifi", Context.MODE_PRIVATE));
            xmlImport(handler.mobile, getSharedPreferences("other", Context.MODE_PRIVATE));
            xmlImport(handler.unused, getSharedPreferences("unused", Context.MODE_PRIVATE));
            xmlImport(handler.screen_wifi, getSharedPreferences("screen_wifi", Context.MODE_PRIVATE));
            xmlImport(handler.screen_other, getSharedPreferences("screen_other", Context.MODE_PRIVATE));
            xmlImport(handler.roaming, getSharedPreferences("roaming", Context.MODE_PRIVATE));
        } finally {
            dh.close();
        }

        // Upgrade imported settings
        Receiver.upgrade(true, this);

        // Refresh UI
        prefs.edit().putBoolean("imported", true).apply();
        prefs.registerOnSharedPreferenceChangeListener(this);
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
            else if (value instanceof String)
                editor.putString(key, (String) value);
            else if (value instanceof Set)
                editor.putStringSet(key, (Set<String>) value);
            else
                Log.e(TAG, "Unknown type=" + value.getClass());
        }

        editor.apply();
    }

    private class XmlImportHandler extends DefaultHandler {
        private Context context;
        private DatabaseHelper dh;
        public boolean enabled = false;
        public Map<String, Object> application = new HashMap<>();
        public Map<String, Object> wifi = new HashMap<>();
        public Map<String, Object> mobile = new HashMap<>();
        public Map<String, Object> unused = new HashMap<>();
        public Map<String, Object> screen_wifi = new HashMap<>();
        public Map<String, Object> screen_other = new HashMap<>();
        public Map<String, Object> roaming = new HashMap<>();
        private Map<String, Object> current = null;
        private List<Integer> listUid = new ArrayList<>();

        public XmlImportHandler(Context context, DatabaseHelper dh) {
            this.context = context;
            this.dh = dh;
        }

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

            else if (qName.equals("filter"))
                current = null;

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
                        // Pro features
                        if (current == application)
                            if ("log".equals(key)) {
                                if (!IAB.isPurchased(ActivityPro.SKU_LOG, context))
                                    return;
                            } else if ("theme".equals(key)) {
                                if (!IAB.isPurchased(ActivityPro.SKU_THEME, context))
                                    return;
                            } else if ("show_stats".equals(key)) {
                                if (!IAB.isPurchased(ActivityPro.SKU_SPEED, context))
                                    return;
                            }

                        if ("boolean".equals(type))
                            current.put(key, Boolean.parseBoolean(value));
                        else if ("integer".equals(type))
                            current.put(key, Integer.parseInt(value));
                        else if ("string".equals(type))
                            current.put(key, value);
                        else if ("set".equals(type)) {
                            Set<String> set = new HashSet<>();
                            if (!TextUtils.isEmpty(value))
                                for (String s : value.split("\n"))
                                    set.add(s);
                            current.put(key, set);
                        } else
                            Log.e(TAG, "Unknown type key=" + key);
                    }
                }
            } else if (qName.equals("rule")) {
                String pkg = attributes.getValue("pkg");

                String version = attributes.getValue("version");
                String protocol = attributes.getValue("protocol");

                Packet packet = new Packet();
                packet.version = (version == null ? 4 : Integer.parseInt(version));
                packet.protocol = (protocol == null ? 6 /* TCP */ : Integer.parseInt(protocol));
                packet.daddr = attributes.getValue("daddr");
                packet.dport = Integer.parseInt(attributes.getValue("dport"));
                packet.time = Long.parseLong(attributes.getValue("time"));

                int block = Integer.parseInt(attributes.getValue("block"));

                try {
                    if ("root".equals(pkg))
                        packet.uid = 0;
                    else
                        packet.uid = getPackageManager().getApplicationInfo(pkg, 0).uid;

                    // This assumes ordered export
                    if (!listUid.contains(packet.uid)) {
                        Log.i(TAG, "Clear filters uid=" + packet.uid);
                        listUid.add(packet.uid);
                        dh.clearAccess(packet.uid);
                    }

                    Log.i(TAG, " Update access " + packet + " block=" + block);
                    dh.updateAccess(packet, null, block);
                } catch (PackageManager.NameNotFoundException ex) {
                    Log.w(TAG, "Package not found pkg=" + pkg);
                }

            } else
                Log.e(TAG, "Unknown element qname=" + qName);
        }
    }
}
