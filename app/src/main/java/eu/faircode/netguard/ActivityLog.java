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

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.Toast;

import java.text.SimpleDateFormat;

public class ActivityLog extends AppCompatActivity {
    private ListView lvLog;
    private LogAdapter adapter;
    private DatabaseHelper dh;

    private DatabaseHelper.LogChangedListener listener = new DatabaseHelper.LogChangedListener() {
        @Override
        public void onChanged() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    adapter = new LogAdapter(ActivityLog.this, dh.getLog());
                    lvLog.setAdapter(adapter);
                }
            });
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.logview);

        getSupportActionBar().setTitle(R.string.title_log);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        dh = new DatabaseHelper(this);

        lvLog = (ListView) findViewById(R.id.lvLog);

        adapter = new LogAdapter(this, dh.getLog());
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
                if (!TextUtils.isEmpty(whois) && getPackageManager().resolveActivity(lookupIP, 0) != null)
                    popup.getMenu().add(Menu.NONE, 2, 2, getString(R.string.title_log_whois, whois));
                if (port > 0 && getPackageManager().resolveActivity(lookupPort, 0) != null)
                    popup.getMenu().add(Menu.NONE, 3, 3, getString(R.string.title_log_port, port));
                popup.getMenu().add(Menu.NONE, 4, 4, SimpleDateFormat.getDateTimeInstance().format(time)).setEnabled(false);

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

        DatabaseHelper.addLogChangedListener(listener);
    }

    @Override
    protected void onDestroy() {
        DatabaseHelper.removeLocationChangedListener(listener);
        dh.close();
        super.onDestroy();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.log, menu);
        return true;
    }

    public boolean onPrepareOptionsMenu(Menu menu) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        menu.findItem(R.id.menu_enabled).setChecked(prefs.getBoolean("log", true));
        return super.onPrepareOptionsMenu(menu);
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.menu_enabled:
                item.setChecked(!item.isChecked());
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
                prefs.edit().putBoolean("log", item.isChecked()).apply();
                SinkholeService.reload(null, "setting changed", this);
                return true;
            case R.id.menu_clear:
                dh.clear();
                return true;
            case R.id.menu_support:
                Intent intent = new Intent(Intent.ACTION_VIEW);
                intent.setData(Uri.parse("https://github.com/M66B/NetGuard/blob/master/FAQ.md#FAQ27"));
                if (getPackageManager().resolveActivity(intent, 0) != null)
                    startActivity(intent);
                return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
