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

import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.Toast;

import java.net.InetAddress;

public class ActivityForwarding extends AppCompatActivity {
    private boolean running;
    private DatabaseHelper dh;
    private ListView lvForwarding;
    private ForwardingAdapter adapter;
    private AlertDialog dialog = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.forwarding);
        running = true;

        getSupportActionBar().setTitle(R.string.setting_forwarding);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);


        dh = new DatabaseHelper(this);

        lvForwarding = (ListView) findViewById(R.id.lvForwarding);
        adapter = new ForwardingAdapter(this, dh.getForwarding());
        lvForwarding.setAdapter(adapter);

        lvForwarding.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                PackageManager pm = getPackageManager();
                Cursor cursor = (Cursor) adapter.getItem(position);
                final int protocol = cursor.getInt(cursor.getColumnIndex("protocol"));
                final int dport = cursor.getInt(cursor.getColumnIndex("dport"));
                final String raddr = cursor.getString(cursor.getColumnIndex("raddr"));
                final int rport = cursor.getInt(cursor.getColumnIndex("rport"));

                PopupMenu popup = new PopupMenu(ActivityForwarding.this, view);
                popup.inflate(R.menu.forward);
                popup.getMenu().findItem(R.id.menu_port).setTitle(dport + " > " + raddr + "/" + rport);

                popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
                    @Override
                    public boolean onMenuItemClick(MenuItem menuItem) {
                        if (menuItem.getItemId() == R.id.menu_delete) {
                            dh.deleteForward(protocol, dport);
                            SinkholeService.reload(null, "forwarding", ActivityForwarding.this);
                            adapter = new ForwardingAdapter(ActivityForwarding.this, dh.getForwarding());
                            lvForwarding.setAdapter(adapter);
                        }
                        return false;
                    }
                });

                popup.show();
            }
        });
    }

    @Override
    protected void onDestroy() {
        dh.close();
        running = false;
        if (dialog != null) {
            dialog.dismiss();
            dialog = null;
        }
        super.onDestroy();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.forwarding, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case R.id.menu_add:
                LayoutInflater inflater = LayoutInflater.from(this);
                View view = inflater.inflate(R.layout.forwardadd, null);
                final EditText etProtocol = (EditText) view.findViewById(R.id.etProtocol);
                final EditText etDPort = (EditText) view.findViewById(R.id.etDPort);
                final EditText etRAddr = (EditText) view.findViewById(R.id.etRAddr);
                final EditText etRPort = (EditText) view.findViewById(R.id.etRPort);
                final EditText etRUid = (EditText) view.findViewById(R.id.etRUid);

                etRAddr.setText("127.0.0.1");

                dialog = new AlertDialog.Builder(this)
                        .setView(view)
                        .setCancelable(false)
                        .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                try {
                                    final int protocol = Integer.parseInt(etProtocol.getText().toString());
                                    final int dport = Integer.parseInt(etDPort.getText().toString());
                                    final String raddr = etRAddr.getText().toString();
                                    final int rport = Integer.parseInt(etRPort.getText().toString());
                                    final int ruid = Integer.parseInt(etRUid.getText().toString());
                                    new AsyncTask<Object, Object, Throwable>() {
                                        @Override
                                        protected Throwable doInBackground(Object... objects) {
                                            try {
                                                InetAddress.getByName(raddr);
                                                dh.addForward(protocol, dport, raddr, rport, ruid);
                                                return null;
                                            } catch (Throwable ex) {
                                                return ex;
                                            }
                                        }

                                        @Override
                                        protected void onPostExecute(Throwable ex) {
                                            if (running)
                                                if (ex == null) {
                                                    SinkholeService.reload(null, "forwarding", ActivityForwarding.this);
                                                    adapter = new ForwardingAdapter(ActivityForwarding.this, dh.getForwarding());
                                                    lvForwarding.setAdapter(adapter);
                                                } else
                                                    Toast.makeText(ActivityForwarding.this, ex.toString(), Toast.LENGTH_LONG).show();
                                        }
                                    }.execute();
                                } catch (Throwable ex) {
                                    Toast.makeText(ActivityForwarding.this, ex.toString(), Toast.LENGTH_LONG).show();
                                }
                            }
                        })
                        .setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialog, int which) {
                                dialog.dismiss();
                            }
                        })
                        .setOnDismissListener(new DialogInterface.OnDismissListener() {
                            @Override
                            public void onDismiss(DialogInterface dialogInterface) {
                                dialog = null;
                            }
                        })
                        .create();
                dialog.show();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }
}
