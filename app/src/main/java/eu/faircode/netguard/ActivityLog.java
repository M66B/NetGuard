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
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;

public class ActivityLog extends AppCompatActivity {
    private static final String TAG = "NetGuard.Log";

    private ListView lvLog;
    private LogAdapter adapter;
    private DatabaseHelper dh;
    private boolean live;
    private boolean resolve;

    private static final int REQUEST_PCAP = 1;

    private DatabaseHelper.LogChangedListener listener = new DatabaseHelper.LogChangedListener() {
        @Override
        public void onChanged() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    adapter.changeCursor(dh.getLog());
                }
            });
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.logview);

        getSupportActionBar().setTitle(R.string.menu_log);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        resolve = prefs.getBoolean("resolve", false);

        lvLog = (ListView) findViewById(R.id.lvLog);

        dh = new DatabaseHelper(this);
        adapter = new LogAdapter(this, dh.getLog(), resolve);
        lvLog.setAdapter(adapter);

        lvLog.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                Cursor cursor = (Cursor) adapter.getItem(position);
                long time = cursor.getLong(cursor.getColumnIndex("time"));
                String ip = cursor.getString(cursor.getColumnIndex("ip"));
                final int port = (cursor.isNull(cursor.getColumnIndex("port")) ? -1 : cursor.getInt(cursor.getColumnIndex("port")));
                final int uid = (cursor.isNull(cursor.getColumnIndex("uid")) ? -1 : cursor.getInt(cursor.getColumnIndex("uid")));
                final String whois = (ip.length() > 1 && ip.charAt(0) == '/' ? ip.substring(1) : ip);

                String name = null;
                PackageManager pm = getPackageManager();
                String[] pkg = pm.getPackagesForUid(uid);
                if (pkg != null && pkg.length > 0)
                    try {
                        ApplicationInfo info = pm.getApplicationInfo(pkg[0], 0);
                        name = pm.getApplicationLabel(info).toString();
                    } catch (PackageManager.NameNotFoundException ignored) {
                    }

                final Intent lookupIP = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.tcpiputils.com/whois-lookup/" + whois));
                final Intent lookupPort = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.speedguide.net/port.php?port=" + port));

                PopupMenu popup = new PopupMenu(ActivityLog.this, findViewById(R.id.vwPopupAnchor), Gravity.CENTER);

                if (uid > 0)
                    popup.getMenu().add(Menu.NONE, 1, 1, name == null ? Integer.toString(uid) : name);

                if (!TextUtils.isEmpty(whois))
                    popup.getMenu().add(Menu.NONE, 2, 2, getString(R.string.title_log_whois, whois))
                            .setEnabled(pm.resolveActivity(lookupIP, 0) != null);

                if (port > 0)
                    popup.getMenu().add(Menu.NONE, 3, 3, getString(R.string.title_log_port, port))
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
            DatabaseHelper.addLogChangedListener(listener);
            adapter.changeCursor(dh.getLog());
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (live)
            DatabaseHelper.removeLocationChangedListener(listener);
    }

    @Override
    protected void onDestroy() {
        dh.close();
        super.onDestroy();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.log, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        boolean log = prefs.getBoolean("log", false);
        boolean resolve = prefs.getBoolean("resolve", false);
        boolean filter = prefs.getBoolean("filter", false);
        boolean pcap_enabled = prefs.getBoolean("pcap", false);
        File pcap_file = new File(getCacheDir(), "netguard.pcap");
        boolean export = (getPackageManager().resolveActivity(getIntentPCAPDocument(), 0) != null);

        menu.findItem(R.id.menu_log_enabled).setChecked(log);
        menu.findItem(R.id.menu_log_resolve).setChecked(resolve);
        menu.findItem(R.id.menu_pcap_enabled).setChecked(pcap_enabled);
        menu.findItem(R.id.menu_pcap_enabled).setEnabled(log || filter);
        menu.findItem(R.id.menu_pcap_export).setEnabled(pcap_file.exists() && export);

        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        File pcap_file = new File(getCacheDir(), "netguard.pcap");

        switch (item.getItemId()) {
            case R.id.menu_log_enabled:
                item.setChecked(!item.isChecked());
                prefs.edit().putBoolean("log", item.isChecked()).apply();
                SinkholeService.reload(null, "setting changed", this);
                return true;

            case R.id.menu_log_live:
                item.setChecked(!item.isChecked());
                live = item.isChecked();
                if (live) {
                    DatabaseHelper.addLogChangedListener(listener);
                    adapter.changeCursor(dh.getLog());
                } else
                    DatabaseHelper.removeLocationChangedListener(listener);
                return true;

            case R.id.menu_log_resolve:
                item.setChecked(!item.isChecked());
                resolve = item.isChecked();
                prefs.edit().putBoolean("resolve", resolve).apply();
                adapter = new LogAdapter(this, dh.getLog(), resolve);
                lvLog.setAdapter(adapter);
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
                dh.clear();
                adapter.changeCursor(dh.getLog());
                if (prefs.getBoolean("pcap", false)) {
                    SinkholeService.setPcap(null);
                    pcap_file.delete();
                    SinkholeService.setPcap(pcap_file);
                } else {
                    if (pcap_file.exists())
                        pcap_file.delete();
                }
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

    private static Intent getIntentPCAPDocument() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/octet-stream");
        intent.putExtra(Intent.EXTRA_TITLE, "netguard_" + new SimpleDateFormat("yyyyMMdd").format(new Date().getTime()) + ".pcap");
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
                    Log.i(TAG, "Export PCAP URI=" + data.getData());
                    out = getContentResolver().openOutputStream(data.getData());

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
