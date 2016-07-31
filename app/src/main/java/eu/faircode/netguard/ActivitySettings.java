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
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.AssetFileDescriptor;
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
import android.preference.PreferenceFragment;
import android.preference.PreferenceGroup;
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
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.style.ImageSpan;
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
import java.net.UnknownHostException;
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

        PreferenceGroup cat_options = (PreferenceGroup) ((PreferenceGroup) screen.findPreference("screen_options")).findPreference("category_options");
        PreferenceGroup cat_advanced = (PreferenceGroup) ((PreferenceGroup) screen.findPreference("screen_advanced_options")).findPreference("category_advanced_options");
        PreferenceGroup cat_stats = (PreferenceGroup) ((PreferenceGroup) screen.findPreference("screen_stats")).findPreference("category_stats");
        PreferenceGroup cat_backup = (PreferenceGroup) ((PreferenceGroup) screen.findPreference("screen_backup")).findPreference("category_backup");

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
        Set<String> ssids = prefs.getStringSet("wifi_homes", new HashSet<String>());
        if (ssids.size() > 0)
            pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, TextUtils.join(", ", ssids)));
        else
            pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, "-"));

        WifiManager wm = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        List<CharSequence> listSSID = new ArrayList<>();
        List<WifiConfiguration> configs = wm.getConfiguredNetworks();
        if (configs != null)
            for (WifiConfiguration config : configs)
                listSSID.add(config.SSID == null ? "NULL" : config.SSID);
        for (String ssid : ssids)
            if (!listSSID.contains(ssid))
                listSSID.add(ssid);
        pref_wifi_homes.setEntries(listSSID.toArray(new CharSequence[0]));
        pref_wifi_homes.setEntryValues(listSSID.toArray(new CharSequence[0]));

        // Filtering always enabled
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP)
            screen.findPreference("filter").setEnabled(false);

        Preference pref_reset_usage = screen.findPreference("reset_usage");
        pref_reset_usage.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                Util.areYouSure(ActivitySettings.this, R.string.setting_reset_usage, new Util.DoubtListener() {
                    @Override
                    public void onSure() {
                        new AsyncTask<Object, Object, Throwable>() {
                            @Override
                            protected Throwable doInBackground(Object... objects) {
                                try {
                                    DatabaseHelper.getInstance(ActivitySettings.this).resetUsage(-1);
                                    return null;
                                } catch (Throwable ex) {
                                    return ex;
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
                });
                return false;
            }
        });

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
        List<String> def_dns = Util.getDefaultDNS(this);
        pref_dns.getEditText().setHint(def_dns.get(0));
        pref_dns.setTitle(getString(R.string.setting_dns, prefs.getString("dns", def_dns.get(0))));

        // SOCKS5 parameters
        screen.findPreference("socks5_addr").setTitle(getString(R.string.setting_socks5_addr, prefs.getString("socks5_addr", "-")));
        screen.findPreference("socks5_port").setTitle(getString(R.string.setting_socks5_port, prefs.getString("socks5_port", "-")));
        screen.findPreference("socks5_username").setTitle(getString(R.string.setting_socks5_username, prefs.getString("socks5_username", "-")));
        screen.findPreference("socks5_password").setTitle(getString(R.string.setting_socks5_password, TextUtils.isEmpty(prefs.getString("socks5_username", "")) ? "-" : "*****"));

        // PCAP parameters
        screen.findPreference("pcap_record_size").setTitle(getString(R.string.setting_pcap_record_size, prefs.getString("pcap_record_size", "64")));
        screen.findPreference("pcap_file_size").setTitle(getString(R.string.setting_pcap_file_size, prefs.getString("pcap_file_size", "2")));

        // Watchdog
        screen.findPreference("watchdog").setTitle(getString(R.string.setting_watchdog, prefs.getString("watchdog", "0")));

        // Handle stats
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            cat_stats.removePreference(screen.findPreference("show_top"));
        EditTextPreference pref_stats_frequency = (EditTextPreference) screen.findPreference("stats_frequency");
        EditTextPreference pref_stats_samples = (EditTextPreference) screen.findPreference("stats_samples");
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
        Preference pref_block_domains = screen.findPreference("use_hosts");
        Preference pref_hosts_import = screen.findPreference("hosts_import");
        EditTextPreference pref_hosts_url = (EditTextPreference) screen.findPreference("hosts_url");
        final Preference pref_hosts_download = screen.findPreference("hosts_download");

        if (Util.isPlayStoreInstall(this)) {
            Log.i(TAG, "Play store install");
            cat_options.removePreference(screen.findPreference("update_check"));
            cat_advanced.removePreference(pref_block_domains);
            cat_advanced.removePreference(pref_forwarding);
            cat_backup.removePreference(pref_hosts_import);
            cat_backup.removePreference(pref_hosts_url);
            cat_backup.removePreference(pref_hosts_download);

        } else {
            String last_import = prefs.getString("hosts_last_import", null);
            String last_download = prefs.getString("hosts_last_download", null);
            if (last_import != null)
                pref_hosts_import.setSummary(getString(R.string.msg_import_last, last_import));
            if (last_download != null)
                pref_hosts_download.setSummary(getString(R.string.msg_download_last, last_download));

            // Handle hosts import
            // https://github.com/Free-Software-for-Android/AdAway/wiki/HostsSources
            pref_hosts_import.setEnabled(getIntentOpenHosts().resolveActivity(getPackageManager()) != null);
            pref_hosts_import.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
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
                                prefs.edit().putString("hosts_last_download", last).apply();

                                if (running) {
                                    pref_hosts_download.setSummary(getString(R.string.msg_download_last, last));
                                    Toast.makeText(ActivitySettings.this, R.string.msg_downloaded, Toast.LENGTH_LONG).show();
                                }

                                ServiceSinkhole.reload("hosts file download", ActivitySettings.this);
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
        if (!Util.isDebuggable(this))
            screen.removePreference(screen.findPreference("screen_development"));
        else {
            // Show resolved
            Preference pref_show_resolved = screen.findPreference("show_resolved");
            pref_show_resolved.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    startActivity(new Intent(ActivitySettings.this, ActivityDns.class));
                    return true;
                }
            });
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

        markPro(screen.findPreference("theme"), ActivityPro.SKU_THEME);
        markPro(screen.findPreference("install"), ActivityPro.SKU_NOTIFY);
        markPro(screen.findPreference("show_stats"), ActivityPro.SKU_SPEED);
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
        } else if ("install".equals(name)) {
            if (prefs.getBoolean(name, false) && !IAB.isPurchased(ActivityPro.SKU_NOTIFY, this)) {
                prefs.edit().putBoolean(name, false).apply();
                ((TwoStatePreference) getPreferenceScreen().findPreference(name)).setChecked(false);
                startActivity(new Intent(this, ActivityPro.class));
                return;
            }
        } else if ("show_stats".equals(name)) {
            if (prefs.getBoolean(name, false) && !IAB.isPurchased(ActivityPro.SKU_SPEED, this)) {
                prefs.edit().putBoolean(name, false).apply();
                startActivity(new Intent(this, ActivityPro.class));
                return;
            }
            ((TwoStatePreference) getPreferenceScreen().findPreference(name)).setChecked(prefs.getBoolean(name, false));
        }

        Object value = prefs.getAll().get(name);
        if (value instanceof String && "".equals(value))
            prefs.edit().remove(name).apply();

        // Dependencies
        if ("whitelist_wifi".equals(name) ||
                "screen_wifi".equals(name))
            ServiceSinkhole.reload("changed " + name, this);

        else if ("whitelist_other".equals(name) ||
                "screen_other".equals(name))
            ServiceSinkhole.reload("changed " + name, this);

        else if ("whitelist_roaming".equals(name)) {
            if (prefs.getBoolean(name, false)) {
                if (Util.hasPhoneStatePermission(this))
                    ServiceSinkhole.reload("changed " + name, this);
                else
                    requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_ROAMING_INTERNATIONAL);
            } else
                ServiceSinkhole.reload("changed " + name, this);

        } else if ("auto_enable".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_auto, prefs.getString(name, "0")));

        else if ("screen_delay".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_delay, prefs.getString(name, "0")));

        else if ("theme".equals(name) || "dark_theme".equals(name))
            recreate();

        else if ("subnet".equals(name))
            ServiceSinkhole.reload("changed " + name, this);

        else if ("tethering".equals(name))
            ServiceSinkhole.reload("changed " + name, this);

        else if ("lan".equals(name))
            ServiceSinkhole.reload("changed " + name, this);

        else if ("ip6".equals(name))
            ServiceSinkhole.reload("changed " + name, this);

        else if ("wifi_homes".equals(name)) {
            MultiSelectListPreference pref_wifi_homes = (MultiSelectListPreference) getPreferenceScreen().findPreference(name);
            Set<String> ssid = prefs.getStringSet(name, new HashSet<String>());
            if (ssid.size() > 0)
                pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, TextUtils.join(", ", ssid)));
            else
                pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, "-"));
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("use_metered".equals(name))
            ServiceSinkhole.reload("changed " + name, this);

        else if ("unmetered_2g".equals(name) ||
                "unmetered_3g".equals(name) ||
                "unmetered_4g".equals(name)) {
            if (prefs.getBoolean(name, false)) {
                if (Util.hasPhoneStatePermission(this))
                    ServiceSinkhole.reload("changed " + name, this);
                else {
                    if ("unmetered_2g".equals(name))
                        requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_METERED2);
                    else if ("unmetered_3g".equals(name))
                        requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_METERED3);
                    else if ("unmetered_4g".equals(name))
                        requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_METERED4);
                }
            } else
                ServiceSinkhole.reload("changed " + name, this);

        } else if ("national_roaming".equals(name)) {
            if (prefs.getBoolean(name, false)) {
                if (Util.hasPhoneStatePermission(this))
                    ServiceSinkhole.reload("changed " + name, this);
                else
                    requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_ROAMING_NATIONAL);
            } else
                ServiceSinkhole.reload("changed " + name, this);


        } else if ("manage_system".equals(name)) {
            boolean manage = prefs.getBoolean(name, false);
            if (!manage)
                prefs.edit().putBoolean("show_user", true).apply();
            prefs.edit().putBoolean("show_system", manage).apply();
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("log_app".equals(name)) {
            Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
            LocalBroadcastManager.getInstance(this).sendBroadcast(ruleset);

        } else if ("filter".equals(name)) {
            ServiceSinkhole.reload("changed " + name, this);

            // Show dialog
            if (prefs.getBoolean(name, false)) {
                LayoutInflater inflater = LayoutInflater.from(ActivitySettings.this);
                View view = inflater.inflate(R.layout.filter, null, false);
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
            ServiceSinkhole.reload("changed " + name, this);

        else if ("vpn4".equals(name)) {
            String vpn4 = prefs.getString(name, null);
            try {
                checkAddress(vpn4);
            } catch (Throwable ex) {
                prefs.edit().remove(name).apply();
                ((EditTextPreference) getPreferenceScreen().findPreference(name)).setText(null);
                if (!TextUtils.isEmpty(vpn4))
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_vpn4, prefs.getString(name, "10.1.10.1")));
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("vpn6".equals(name)) {
            String vpn6 = prefs.getString(name, null);
            try {
                checkAddress(vpn6);
            } catch (Throwable ex) {
                prefs.edit().remove(name).apply();
                ((EditTextPreference) getPreferenceScreen().findPreference(name)).setText(null);
                if (!TextUtils.isEmpty(vpn6))
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_vpn6, prefs.getString(name, "fd00:1:fd00:1:fd00:1:fd00:1")));
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("dns".equals(name)) {
            String dns = prefs.getString(name, null);
            try {
                checkAddress(dns);
            } catch (Throwable ex) {
                prefs.edit().remove(name).apply();
                ((EditTextPreference) getPreferenceScreen().findPreference(name)).setText(null);
                if (!TextUtils.isEmpty(dns))
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_dns, prefs.getString(name, Util.getDefaultDNS(this).get(0))));
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("socks5_enabled".equals(name))
            ServiceSinkhole.reload("changed " + name, this);

        else if ("socks5_addr".equals(name)) {
            String socks5_addr = prefs.getString(name, null);
            try {
                if (!TextUtils.isEmpty(socks5_addr) && !Util.isNumericAddress(socks5_addr))
                    throw new IllegalArgumentException("Bad address");
            } catch (Throwable ex) {
                prefs.edit().remove(name).apply();
                ((EditTextPreference) getPreferenceScreen().findPreference(name)).setText(null);
                if (!TextUtils.isEmpty(socks5_addr))
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_socks5_addr, prefs.getString(name, "-")));
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("socks5_port".equals(name)) {
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_socks5_port, prefs.getString(name, "-")));
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("socks5_username".equals(name)) {
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_socks5_username, prefs.getString(name, "-")));
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("socks5_password".equals(name)) {
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_socks5_password, TextUtils.isEmpty(prefs.getString(name, "")) ? "-" : "*****"));
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("pcap_record_size".equals(name) || "pcap_file_size".equals(name)) {
            if ("pcap_record_size".equals(name))
                getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_pcap_record_size, prefs.getString(name, "64")));
            else
                getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_pcap_file_size, prefs.getString(name, "2")));

            ServiceSinkhole.setPcap(false, this);

            File pcap_file = new File(getCacheDir(), "netguard.pcap");
            if (pcap_file.exists() && !pcap_file.delete())
                Log.w(TAG, "Delete PCAP failed");

            if (prefs.getBoolean("pcap", false))
                ServiceSinkhole.setPcap(true, this);

        } else if ("watchdog".equals(name)) {
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_watchdog, prefs.getString(name, "0")));
            ServiceSinkhole.reload("changed " + name, this);

        } else if ("show_stats".equals(name))
            ServiceSinkhole.reloadStats("changed " + name, this);

        else if ("stats_frequency".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_stats_frequency, prefs.getString(name, "1000")));

        else if ("stats_samples".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_stats_samples, prefs.getString(name, "90")));

        else if ("hosts_url".equals(name))
            getPreferenceScreen().findPreference(name).setSummary(prefs.getString(name, "http://www.netguard.me/hosts"));

        else if ("loglevel".equals(name))
            ServiceSinkhole.reload("changed " + name, this);
    }

    private void checkAddress(String address) throws IllegalArgumentException, UnknownHostException {
        if (address == null || TextUtils.isEmpty(address.trim()))
            throw new IllegalArgumentException("Bad address");
        if (!Util.isNumericAddress(address))
            throw new IllegalArgumentException("Bad address");
        InetAddress idns = InetAddress.getByName(address);
        if (idns.isLoopbackAddress() || idns.isAnyLocalAddress())
            throw new IllegalArgumentException("Bad address");
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

        boolean granted = (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED);

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
            ServiceSinkhole.reload("permission granted", this);
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

    private void markPro(Preference pref, String sku) {
        if (sku == null || !IAB.isPurchased(sku, this)) {
            SpannableStringBuilder ssb = new SpannableStringBuilder("  " + pref.getTitle());
            ssb.setSpan(new ImageSpan(this, R.drawable.ic_shopping_cart_white_24dp), 0, 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            pref.setTitle(ssb);
        }
    }

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
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) {
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
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT)
            intent = new Intent(Intent.ACTION_GET_CONTENT);
        else
            intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*"); // text/xml
        return intent;
    }

    private Intent getIntentOpenHosts() {
        Intent intent;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT)
            intent = new Intent(Intent.ACTION_GET_CONTENT);
        else
            intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*"); // text/plain
        return intent;
    }

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
                    ContentResolver resolver = getContentResolver();
                    String[] streamTypes = resolver.getStreamTypes(data.getData(), "*/*");
                    String streamType = (streamTypes == null || streamTypes.length == 0 ? "*/*" : streamTypes[0]);
                    AssetFileDescriptor descriptor = resolver.openTypedAssetFileDescriptor(data.getData(), streamType, null);
                    in = descriptor.createInputStream();
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
                        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ActivitySettings.this);
                        String last = SimpleDateFormat.getDateTimeInstance().format(new Date().getTime());
                        prefs.edit().putString("hosts_last_import", last).apply();

                        if (running) {
                            getPreferenceScreen().findPreference("hosts_import").setSummary(getString(R.string.msg_import_last, last));
                            Toast.makeText(ActivitySettings.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                        }

                        ServiceSinkhole.reload("hosts import", ActivitySettings.this);
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
                    ContentResolver resolver = getContentResolver();
                    String[] streamTypes = resolver.getStreamTypes(data.getData(), "*/*");
                    String streamType = (streamTypes == null || streamTypes.length == 0 ? "*/*" : streamTypes[0]);
                    AssetFileDescriptor descriptor = resolver.openTypedAssetFileDescriptor(data.getData(), streamType, null);
                    in = descriptor.createInputStream();
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
                        ServiceSinkhole.reloadStats("import", ActivitySettings.this);
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

        serializer.startTag(null, "apply");
        xmlExport(getSharedPreferences("apply", Context.MODE_PRIVATE), serializer);
        serializer.endTag(null, "apply");

        serializer.startTag(null, "notify");
        xmlExport(getSharedPreferences("notify", Context.MODE_PRIVATE), serializer);
        serializer.endTag(null, "notify");

        serializer.startTag(null, "filter");
        filterExport(serializer);
        serializer.endTag(null, "filter");

        serializer.startTag(null, "forward");
        forwardExport(serializer);
        serializer.endTag(null, "forward");

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
        Cursor cursor = DatabaseHelper.getInstance(this).getAccess();
        int colUid = cursor.getColumnIndex("uid");
        int colVersion = cursor.getColumnIndex("version");
        int colProtocol = cursor.getColumnIndex("protocol");
        int colDAddr = cursor.getColumnIndex("daddr");
        int colDPort = cursor.getColumnIndex("dport");
        int colTime = cursor.getColumnIndex("time");
        int colBlock = cursor.getColumnIndex("block");
        while (cursor.moveToNext())
            for (String pkg : getPackages(cursor.getInt(colUid))) {
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
        cursor.close();
    }

    private void forwardExport(XmlSerializer serializer) throws IOException {
        PackageManager pm = getPackageManager();
        Cursor cursor = DatabaseHelper.getInstance(this).getForwarding();
        int colProtocol = cursor.getColumnIndex("protocol");
        int colDPort = cursor.getColumnIndex("dport");
        int colRAddr = cursor.getColumnIndex("raddr");
        int colRPort = cursor.getColumnIndex("rport");
        int colRUid = cursor.getColumnIndex("ruid");
        while (cursor.moveToNext())
            for (String pkg : getPackages(cursor.getInt(colRUid))) {
                serializer.startTag(null, "port");
                serializer.attribute(null, "pkg", pkg);
                serializer.attribute(null, "protocol", Integer.toString(cursor.getInt(colProtocol)));
                serializer.attribute(null, "dport", Integer.toString(cursor.getInt(colDPort)));
                serializer.attribute(null, "raddr", cursor.getString(colRAddr));
                serializer.attribute(null, "rport", Integer.toString(cursor.getInt(colRPort)));
                serializer.endTag(null, "port");
            }
        cursor.close();
    }

    private String[] getPackages(int uid) {
        if (uid == 0)
            return new String[]{"root"};
        else if (uid == 1013)
            return new String[]{"mediaserver"};
        else if (uid == 9999)
            return new String[]{"nobody"};
        else {
            String pkgs[] = getPackageManager().getPackagesForUid(uid);
            if (pkgs == null)
                return new String[0];
            else
                return pkgs;
        }
    }

    private void xmlImport(InputStream in) throws IOException, SAXException, ParserConfigurationException {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.unregisterOnSharedPreferenceChangeListener(this);
        prefs.edit().putBoolean("enabled", false).apply();
        ServiceSinkhole.stop("import", this);

        XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
        XmlImportHandler handler = new XmlImportHandler(this);
        reader.setContentHandler(handler);
        reader.parse(new InputSource(in));

        xmlImport(handler.application, prefs);
        xmlImport(handler.wifi, getSharedPreferences("wifi", Context.MODE_PRIVATE));
        xmlImport(handler.mobile, getSharedPreferences("other", Context.MODE_PRIVATE));
        xmlImport(handler.unused, getSharedPreferences("unused", Context.MODE_PRIVATE));
        xmlImport(handler.screen_wifi, getSharedPreferences("screen_wifi", Context.MODE_PRIVATE));
        xmlImport(handler.screen_other, getSharedPreferences("screen_other", Context.MODE_PRIVATE));
        xmlImport(handler.roaming, getSharedPreferences("roaming", Context.MODE_PRIVATE));
        xmlImport(handler.apply, getSharedPreferences("apply", Context.MODE_PRIVATE));
        xmlImport(handler.notify, getSharedPreferences("notify", Context.MODE_PRIVATE));

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
        public boolean enabled = false;
        public Map<String, Object> application = new HashMap<>();
        public Map<String, Object> wifi = new HashMap<>();
        public Map<String, Object> mobile = new HashMap<>();
        public Map<String, Object> unused = new HashMap<>();
        public Map<String, Object> screen_wifi = new HashMap<>();
        public Map<String, Object> screen_other = new HashMap<>();
        public Map<String, Object> roaming = new HashMap<>();
        public Map<String, Object> apply = new HashMap<>();
        public Map<String, Object> notify = new HashMap<>();
        private Map<String, Object> current = null;

        public XmlImportHandler(Context context) {
            this.context = context;
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

            else if (qName.equals("apply"))
                current = apply;

            else if (qName.equals("notify"))
                current = notify;

            else if (qName.equals("filter")) {
                current = null;
                Log.i(TAG, "Clearing filters");
                DatabaseHelper.getInstance(context).clearAccess();

            } else if (qName.equals("forward")) {
                current = null;
                Log.i(TAG, "Clearing forwards");
                DatabaseHelper.getInstance(context).deleteForward();

            } else if (qName.equals("setting")) {
                String key = attributes.getValue("key");
                String type = attributes.getValue("type");
                String value = attributes.getValue("value");

                if (current == null)
                    Log.e(TAG, "No current key=" + key);
                else {
                    if ("enabled".equals(key))
                        enabled = Boolean.parseBoolean(value);
                    else {
                        if (current == application) {
                            // Pro features
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

                            if ("hosts_last_import".equals(key) || "hosts_last_download".equals(key))
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
                    packet.uid = getUid(pkg);
                    DatabaseHelper.getInstance(context).updateAccess(packet, null, block);
                } catch (PackageManager.NameNotFoundException ex) {
                    Log.w(TAG, "Package not found pkg=" + pkg);
                }

            } else if (qName.equals("port")) {
                String pkg = attributes.getValue("pkg");
                int protocol = Integer.parseInt(attributes.getValue("protocol"));
                int dport = Integer.parseInt(attributes.getValue("dport"));
                String raddr = attributes.getValue("raddr");
                int rport = Integer.parseInt(attributes.getValue("rport"));

                try {
                    int uid = getUid(pkg);
                    DatabaseHelper.getInstance(context).addForward(protocol, dport, raddr, rport, uid);
                } catch (PackageManager.NameNotFoundException ex) {
                    Log.w(TAG, "Package not found pkg=" + pkg);
                }

            } else
                Log.e(TAG, "Unknown element qname=" + qName);
        }

        private int getUid(String pkg) throws PackageManager.NameNotFoundException {
            if ("root".equals(pkg))
                return 0;
            else if ("mediaserver".equals(pkg))
                return 1013;
            else if ("nobody".equals(pkg))
                return 9999;
            else
                return getPackageManager().getApplicationInfo(pkg, 0).uid;
        }
    }
}
