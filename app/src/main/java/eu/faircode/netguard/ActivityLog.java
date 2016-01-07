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
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.ListView;
import android.widget.Toast;

public class ActivityLog extends AppCompatActivity {
    private ListView lvLog;
    private DatabaseHelper dh;

    private DatabaseHelper.LogChangedListener listener = new DatabaseHelper.LogChangedListener() {
        @Override
        public void onChanged() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    LogAdapter adapter = new LogAdapter(ActivityLog.this, dh.getLog());
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
        LogAdapter adapter = new LogAdapter(this, dh.getLog());
        lvLog.setAdapter(adapter);

        DatabaseHelper.addLogChangedListener(listener);

        Toast.makeText(this, getString(R.string.title_log_info), Toast.LENGTH_SHORT).show();
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

    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.menu_clear:
                dh.clear();
                return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
