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

import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v4.app.NavUtils;
import android.support.v4.view.MenuItemCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.SearchView;
import android.support.v7.widget.SwitchCompat;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.CompoundButton;
import android.widget.FilterQueryProvider;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ActivityLog extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Log";

    private boolean running = false;
    private ListView lvLog;
    private LogAdapter adapter;
    private MenuItem menuSearch = null;

    private DatabaseHelper dh;
    private boolean live;
    private boolean resolve;
    private InetAddress vpn4 = null;
    private InetAddress vpn6 = null;

    private static final int REQUEST_PCAP = 1;

    private DatabaseHelper.LogChangedListener listener = new DatabaseHelper.LogChangedListener() {
        @Override
        public void onChanged() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    updateAdapter();
                }
            });
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.logging);
        running = true;

        // Action bar
        View actionView = getLayoutInflater().inflate(R.layout.action, null);
        SwitchCompat swEnabled = (SwitchCompat) actionView.findViewById(R.id.swEnabled);

        getSupportActionBar().setDisplayShowCustomEnabled(true);
        getSupportActionBar().setCustomView(actionView);

        getSupportActionBar().setTitle(R.string.menu_log);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        // Get settings
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        resolve = prefs.getBoolean("resolve", false);
        boolean log = prefs.getBoolean("log", false);

        // Show disabled message
        TextView tvDisabled = (TextView) findViewById(R.id.tvDisabled);
        tvDisabled.setVisibility(log ? View.GONE : View.VISIBLE);

        // Set enabled switch
        swEnabled.setChecked(log);
        swEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.edit().putBoolean("log", isChecked).apply();
            }
        });

        // Listen for preference changes
        prefs.registerOnSharedPreferenceChangeListener(this);

        lvLog = (ListView) findViewById(R.id.lvLog);

        boolean udp = prefs.getBoolean("proto_udp", true);
        boolean tcp = prefs.getBoolean("proto_tcp", true);
        boolean other = prefs.getBoolean("proto_other", true);
        boolean allowed = prefs.getBoolean("traffic_allowed", true);
        boolean blocked = prefs.getBoolean("traffic_blocked", true);

        dh = new DatabaseHelper(this);
        adapter = new LogAdapter(this, dh.getLog(udp, tcp, other, allowed, blocked), resolve);
        adapter.setFilterQueryProvider(new FilterQueryProvider() {
            public Cursor runQuery(CharSequence constraint) {
                return dh.searchLog(constraint.toString());
            }
        });

        lvLog.setAdapter(adapter);

        try {
            vpn4 = InetAddress.getByName(prefs.getString("vpn4", "10.1.10.1"));
            vpn6 = InetAddress.getByName(prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1"));
        } catch (UnknownHostException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        lvLog.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                PackageManager pm = getPackageManager();
                Cursor cursor = (Cursor) adapter.getItem(position);
                long time = cursor.getLong(cursor.getColumnIndex("time"));
                final String daddr = cursor.getString(cursor.getColumnIndex("daddr"));
                final int dport = (cursor.isNull(cursor.getColumnIndex("dport")) ? -1 : cursor.getInt(cursor.getColumnIndex("dport")));
                final String saddr = cursor.getString(cursor.getColumnIndex("saddr"));
                final int sport = (cursor.isNull(cursor.getColumnIndex("sport")) ? -1 : cursor.getInt(cursor.getColumnIndex("sport")));
                final int uid = (cursor.isNull(cursor.getColumnIndex("uid")) ? -1 : cursor.getInt(cursor.getColumnIndex("uid")));

                // Get external address
                InetAddress addr = null;
                try {
                    addr = InetAddress.getByName(daddr);
                } catch (UnknownHostException ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

                String ip;
                int port;
                if (addr.equals(vpn4) || addr.equals(vpn6)) {
                    ip = saddr;
                    port = sport;
                } else {
                    ip = daddr;
                    port = dport;
                }

                // Build popup menu
                PopupMenu popup = new PopupMenu(ActivityLog.this, findViewById(R.id.vwPopupAnchor));

                if (uid >= 0)
                    popup.getMenu().add(Menu.NONE, 1, 1, TextUtils.join(", ", Util.getApplicationNames(uid, ActivityLog.this)));

                final Intent lookupIP = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.tcpiputils.com/whois-lookup/" + ip));
                popup.getMenu().add(Menu.NONE, 2, 2, getString(R.string.title_log_whois, ip))
                        .setEnabled(pm.resolveActivity(lookupIP, 0) != null);

                final Intent lookupPort = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.speedguide.net/port.php?port=" + port));
                if (port > 0)
                    popup.getMenu().add(Menu.NONE, 3, 3, getString(R.string.title_log_port, dport))
                            .setEnabled(pm.resolveActivity(lookupPort, 0) != null);

                popup.getMenu().add(Menu.NONE, 4, 4, SimpleDateFormat.getDateTimeInstance().format(time))
                        .setEnabled(false);

                popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
                    @Override
                    public boolean onMenuItemClick(MenuItem menuItem) {
                        if (menuItem.getItemId() == 1) {
                            Intent main = new Intent(ActivityLog.this, ActivityMain.class);
                            main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
                            startActivity(main);
                        } else if (menuItem.getItemId() == 2)
                            startActivity(lookupIP);
                        else if (menuItem.getItemId() == 3)
                            startActivity(lookupPort);
                        return false;
                    }
                });

                popup.show();
            }
        });

        live = true;
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (live) {
            dh.addLogChangedListener(listener);
            updateAdapter();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (live)
            dh.removeLogChangedListener(listener);
    }

    @Override
    protected void onDestroy() {
        running = false;
        dh.close();
        PreferenceManager.getDefaultSharedPreferences(this).unregisterOnSharedPreferenceChangeListener(this);
        super.onDestroy();
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        Log.i(TAG, "Preference " + name + "=" + prefs.getAll().get(name));
        if ("log".equals(name)) {
            // Get enabled
            boolean log = prefs.getBoolean(name, false);

            // Display disabled warning
            TextView tvDisabled = (TextView) findViewById(R.id.tvDisabled);
            tvDisabled.setVisibility(log ? View.GONE : View.VISIBLE);

            // Check switch state
            SwitchCompat swEnabled = (SwitchCompat) getSupportActionBar().getCustomView().findViewById(R.id.swEnabled);
            if (swEnabled.isChecked() != log)
                swEnabled.setChecked(log);

            SinkholeService.reload(null, "changed " + name, ActivityLog.this);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.log, menu);

        menuSearch = menu.findItem(R.id.menu_search);
        SearchView searchView = (SearchView) MenuItemCompat.getActionView(menuSearch);
        searchView.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
            @Override
            public boolean onQueryTextSubmit(String query) {
                if (adapter != null)
                    adapter.getFilter().filter(query);
                return true;
            }

            @Override
            public boolean onQueryTextChange(String newText) {
                if (adapter != null)
                    adapter.getFilter().filter(newText);
                return true;
            }
        });
        searchView.setOnCloseListener(new SearchView.OnCloseListener() {
            @Override
            public boolean onClose() {
                if (adapter != null)
                    adapter.getFilter().filter(null);
                return true;
            }
        });

        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // https://gist.github.com/granoeste/5574148
        File pcap_file = new File(getCacheDir(), "netguard.pcap");

        boolean export = (getPackageManager().resolveActivity(getIntentPCAPDocument(), 0) != null);

        menu.findItem(R.id.menu_protocol_udp).setChecked(prefs.getBoolean("proto_udp", true));
        menu.findItem(R.id.menu_protocol_tcp).setChecked(prefs.getBoolean("proto_tcp", true));
        menu.findItem(R.id.menu_protocol_other).setChecked(prefs.getBoolean("proto_other", true));
        menu.findItem(R.id.menu_traffic_allowed).setEnabled(prefs.getBoolean("filter", false));
        menu.findItem(R.id.menu_traffic_allowed).setChecked(prefs.getBoolean("traffic_allowed", true));
        menu.findItem(R.id.menu_traffic_blocked).setChecked(prefs.getBoolean("traffic_blocked", true));

        menu.findItem(R.id.menu_refresh).setEnabled(!menu.findItem(R.id.menu_log_live).isChecked());
        menu.findItem(R.id.menu_log_resolve).setChecked(prefs.getBoolean("resolve", false));
        menu.findItem(R.id.menu_pcap_enabled).setEnabled(prefs.getBoolean("filter", false));
        menu.findItem(R.id.menu_pcap_enabled).setChecked(prefs.getBoolean("pcap", false));
        menu.findItem(R.id.menu_pcap_export).setEnabled(pcap_file.exists() && export);

        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        final File pcap_file = new File(getCacheDir(), "netguard.pcap");

        switch (item.getItemId()) {
            case android.R.id.home:
                Log.i(TAG, "Up");
                NavUtils.navigateUpFromSameTask(this);
                return true;

            case R.id.menu_protocol_udp:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("proto_udp", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_protocol_tcp:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("proto_tcp", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_protocol_other:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("proto_other", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_traffic_allowed:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("traffic_allowed", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_traffic_blocked:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("traffic_blocked", item.isChecked()).apply();
                updateAdapter();
                return true;

            case R.id.menu_log_live:
                item.setChecked(!item.isChecked());
                live = item.isChecked();
                if (live) {
                    dh.addLogChangedListener(listener);
                    updateAdapter();
                } else
                    dh.removeLogChangedListener(listener);
                return true;

            case R.id.menu_refresh:
                updateAdapter();
                return true;

            case R.id.menu_log_resolve:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("resolve", item.isChecked()).apply();
                adapter.setResolve(item.isChecked());
                adapter.notifyDataSetChanged();
                return true;

            case R.id.menu_pcap_enabled:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("pcap", item.isChecked()).apply();
                SinkholeService.setPcap(item.isChecked() ? pcap_file : null);
                return true;

            case R.id.menu_pcap_export:
                startActivityForResult(getIntentPCAPDocument(), REQUEST_PCAP);
                return true;

            case R.id.menu_log_clear:
                new AsyncTask<Object, Object, Object>() {
                    @Override
                    protected Object doInBackground(Object... objects) {
                        dh.clearLog();
                        if (prefs.getBoolean("pcap", false)) {
                            SinkholeService.setPcap(null);
                            if (pcap_file.exists() && !pcap_file.delete())
                                Log.w(TAG, "Delete PCAP failed");
                            SinkholeService.setPcap(pcap_file);
                        } else {
                            if (pcap_file.exists() && !pcap_file.delete())
                                Log.w(TAG, "Delete PCAP failed");
                        }
                        return null;
                    }

                    @Override
                    protected void onPostExecute(Object result) {
                        if (running)
                            updateAdapter();
                    }
                }.execute();
                return true;

            case R.id.menu_log_support:
                Intent intent = new Intent(Intent.ACTION_VIEW);
                intent.setData(Uri.parse("https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ27"));
                if (getPackageManager().resolveActivity(intent, 0) != null)
                    startActivity(intent);
                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void updateAdapter() {
        if (adapter != null) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            boolean udp = prefs.getBoolean("proto_udp", true);
            boolean tcp = prefs.getBoolean("proto_tcp", true);
            boolean other = prefs.getBoolean("proto_other", true);
            boolean allowed = prefs.getBoolean("traffic_allowed", true);
            boolean blocked = prefs.getBoolean("traffic_blocked", true);
            adapter.changeCursor(dh.getLog(udp, tcp, other, allowed, blocked));
            if (menuSearch != null && menuSearch.isActionViewExpanded()) {
                SearchView searchView = (SearchView) MenuItemCompat.getActionView(menuSearch);
                adapter.getFilter().filter(searchView.getQuery().toString());
            }
        }
    }

    private Intent getIntentPCAPDocument() {
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
            intent.setType("application/octet-stream");
            intent.putExtra(Intent.EXTRA_TITLE, "netguard_" + new SimpleDateFormat("yyyyMMdd").format(new Date().getTime()) + ".pcap");
        }
        return intent;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, final Intent data) {
        Log.i(TAG, "onActivityResult request=" + requestCode + " result=" + requestCode + " ok=" + (resultCode == RESULT_OK));

        if (requestCode == REQUEST_PCAP) {
            if (resultCode == RESULT_OK && data != null)
                handleExportPCAP(data);

        } else {
            Log.w(TAG, "Unknown activity result request=" + requestCode);
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    private void handleExportPCAP(final Intent data) {
        new AsyncTask<Object, Object, Throwable>() {
            @Override
            protected Throwable doInBackground(Object... objects) {
                OutputStream out = null;
                FileInputStream in = null;
                try {
                    // Stop capture
                    SinkholeService.setPcap(null);

                    Uri target = data.getData();
                    if (data.hasExtra("org.openintents.extra.DIR_PATH"))
                        target = Uri.parse(target + "/netguard.pcap");
                    Log.i(TAG, "Export PCAP URI=" + target);
                    out = getContentResolver().openOutputStream(target);

                    File pcap = new File(getCacheDir(), "netguard.pcap");
                    in = new FileInputStream(pcap);

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
                    Util.sendCrashReport(ex, ActivityLog.this);
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

                    // Resume capture
                    SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ActivityLog.this);
                    if (prefs.getBoolean("pcap", false)) {
                        File pcap_file = new File(getCacheDir(), "netguard.pcap");
                        SinkholeService.setPcap(pcap_file);
                    }
                }
            }

            @Override
            protected void onPostExecute(Throwable ex) {
                if (ex == null)
                    Toast.makeText(ActivityLog.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                else
                    Toast.makeText(ActivityLog.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
        }.execute();
    }
}
