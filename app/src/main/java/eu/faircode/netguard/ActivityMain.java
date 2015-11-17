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

import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentSender;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.Uri;
import android.net.VpnService;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v4.view.MenuItemCompat;
import android.support.v4.widget.SwipeRefreshLayout;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.support.v7.widget.SearchView;
import android.support.v7.widget.SwitchCompat;
import android.text.method.LinkMovementMethod;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.TextView;
import android.widget.Toast;

import java.util.List;

public class ActivityMain extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Main";

    private boolean running = false;
    private SwipeRefreshLayout swipeRefresh;
    private RuleAdapter adapter = null;
    private MenuItem menuSearch = null;
    private AlertDialog dialogFirst = null;
    private AlertDialog dialogVpn = null;
    private AlertDialog dialogAbout = null;

    private static final int REQUEST_VPN = 1;
    private static final int REQUEST_IAB = 2;
    private static final int REQUEST_INVITE = 3;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.i(TAG, "Create");

        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        setTheme(prefs.getBoolean("dark_theme", false) ? R.style.AppThemeDark : R.style.AppTheme);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        running = true;
        boolean enabled = prefs.getBoolean("enabled", false);

        if (enabled)
            SinkholeService.start(this);
        else
            SinkholeService.stop(this);

        // Action bar
        View actionView = getLayoutInflater().inflate(R.layout.action, null);
        SwitchCompat swEnabled = (SwitchCompat) actionView.findViewById(R.id.swEnabled);

        getSupportActionBar().setDisplayShowCustomEnabled(true);
        getSupportActionBar().setCustomView(actionView);

        // On/off switch
        swEnabled.setChecked(enabled);
        swEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.edit().putBoolean("enabled", isChecked).apply();

                if (isChecked) {
                    Log.i(TAG, "Switch on");
                    final Intent prepare = VpnService.prepare(ActivityMain.this);
                    if (prepare == null) {
                        Log.e(TAG, "Prepare done");
                        onActivityResult(REQUEST_VPN, RESULT_OK, null);
                    } else {
                        // Show dialog
                        LayoutInflater inflater = LayoutInflater.from(ActivityMain.this);
                        View view = inflater.inflate(R.layout.vpn, null);
                        dialogVpn = new AlertDialog.Builder(ActivityMain.this)
                                .setView(view)
                                .setCancelable(false)
                                .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int which) {
                                        if (running) {
                                            Log.i(TAG, "Start intent=" + prepare);
                                            try {
                                                startActivityForResult(prepare, REQUEST_VPN);
                                            } catch (Throwable ex) {
                                                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                                                onActivityResult(REQUEST_VPN, RESULT_CANCELED, null);
                                                Toast.makeText(ActivityMain.this, ex.toString(), Toast.LENGTH_LONG).show();
                                            }
                                        }
                                    }
                                })
                                .setOnDismissListener(new DialogInterface.OnDismissListener() {
                                    @Override
                                    public void onDismiss(DialogInterface dialogInterface) {
                                        dialogVpn = null;
                                    }
                                })
                                .create();
                        dialogVpn.show();
                    }
                } else {
                    Log.i(TAG, "Switch off");
                    prefs.edit().putBoolean("enabled", false).apply();
                    SinkholeService.stop(ActivityMain.this);
                }
            }
        });

        // Disabled warning
        TextView tvDisabled = (TextView) findViewById(R.id.tvDisabled);
        tvDisabled.setVisibility(enabled ? View.GONE : View.VISIBLE);

        // Application list
        RecyclerView rvApplication = (RecyclerView) findViewById(R.id.rvApplication);
        rvApplication.setHasFixedSize(true);
        rvApplication.setLayoutManager(new LinearLayoutManager(this));
        adapter = new RuleAdapter(ActivityMain.this);
        rvApplication.setAdapter(adapter);

        // Swipe to refresh
        swipeRefresh = (SwipeRefreshLayout) findViewById(R.id.swipeRefresh);
        swipeRefresh.setColorSchemeColors(Color.WHITE, Color.WHITE, Color.WHITE);
        swipeRefresh.setProgressBackgroundColorSchemeResource(R.color.colorPrimary);
        swipeRefresh.setOnRefreshListener(new SwipeRefreshLayout.OnRefreshListener() {
            @Override
            public void onRefresh() {
                updateApplicationList();
            }
        });

        // Fill application list
        updateApplicationList();

        // Listen for preference changes
        prefs.registerOnSharedPreferenceChangeListener(this);

        // Listen for added/removed applications
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(Intent.ACTION_PACKAGE_ADDED);
        intentFilter.addAction(Intent.ACTION_PACKAGE_REMOVED);
        intentFilter.addDataScheme("package");
        registerReceiver(packageChangedReceiver, intentFilter);

        // First use
        if (!prefs.getBoolean("initialized", false)) {
            // Create view
            LayoutInflater inflater = LayoutInflater.from(this);
            View view = inflater.inflate(R.layout.first, null);
            TextView tvFirst = (TextView) view.findViewById(R.id.tvFirst);
            tvFirst.setMovementMethod(LinkMovementMethod.getInstance());

            // Show dialog
            dialogFirst = new AlertDialog.Builder(this)
                    .setView(view)
                    .setCancelable(false)
                    .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            if (running)
                                prefs.edit().putBoolean("initialized", true).apply();
                        }
                    })
                    .setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            finish();
                        }
                    })
                    .setOnDismissListener(new DialogInterface.OnDismissListener() {
                        @Override
                        public void onDismiss(DialogInterface dialogInterface) {
                            dialogFirst = null;
                        }
                    })
                    .create();
            dialogFirst.show();
        }
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");
        running = false;

        PreferenceManager.getDefaultSharedPreferences(this).unregisterOnSharedPreferenceChangeListener(this);

        unregisterReceiver(packageChangedReceiver);

        if (dialogFirst != null) {
            dialogFirst.dismiss();
            dialogFirst = null;
        }
        if (dialogVpn != null) {
            dialogVpn.dismiss();
            dialogVpn = null;
        }
        if (dialogAbout != null) {
            dialogAbout.dismiss();
            dialogAbout = null;
        }

        super.onDestroy();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, final Intent data) {
        Log.i(TAG, "onActivityResult request=" + requestCode + " result=" + requestCode + " ok=" + (resultCode == RESULT_OK));
        Util.logExtras(TAG, data);

        if (requestCode == REQUEST_VPN) {
            // Handle VPN approval
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean("enabled", resultCode == RESULT_OK).apply();
            if (resultCode == RESULT_OK)
                SinkholeService.start(this);

        } else if (requestCode == REQUEST_IAB) {
            if (resultCode == RESULT_OK) {
                // Handle donation
                Intent intent = new Intent(IAB.ACTION_PURCHASED);
                LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
            } else {
                int response = (data == null ? -1 : data.getIntExtra("RESPONSE_CODE", -1));
                Log.i(TAG, "IAB response=" + IAB.getIABResult(response));

                // Fail-safe
                Intent donate = new Intent(Intent.ACTION_VIEW);
                donate.setData(Uri.parse("http://www.netguard.me/"));
                if (donate.resolveActivity(getPackageManager()) != null)
                    startActivity(donate);
            }

        } else if (requestCode == REQUEST_INVITE) {
            // Do nothing

        } else {
            Log.w(TAG, "Unknown activity result request=" + requestCode);
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        Log.i(TAG, "Preference " + name + "=" + prefs.getAll().get(name));
        if ("enabled".equals(name)) {
            // Get enabled
            boolean enabled = prefs.getBoolean(name, false);

            // Display disabled warning
            TextView tvDisabled = (TextView) findViewById(R.id.tvDisabled);
            tvDisabled.setVisibility(enabled ? View.GONE : View.VISIBLE);

            // Check switch state
            SwitchCompat swEnabled = (SwitchCompat) getSupportActionBar().getCustomView().findViewById(R.id.swEnabled);
            if (swEnabled.isChecked() != enabled)
                swEnabled.setChecked(enabled);

        } else if ("whitelist_wifi".equals(name) ||
                "whitelist_other".equals(name) ||
                "unused".equals(name) ||
                "whitelist_roaming".equals(name) ||
                "manage_system".equals(name) ||
                "imported".equals(name))
            updateApplicationList();

        else if ("dark_theme".equals(name))
            recreate();
    }

    private BroadcastReceiver packageChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);
            updateApplicationList();
        }
    };

    private void updateApplicationList() {
        new AsyncTask<Object, Object, List<Rule>>() {
            private boolean refreshing = true;

            @Override
            protected void onPreExecute() {
                swipeRefresh.post(new Runnable() {
                    @Override
                    public void run() {
                        if (refreshing)
                            swipeRefresh.setRefreshing(true);
                    }
                });
            }

            @Override
            protected List<Rule> doInBackground(Object... arg) {
                return Rule.getRules(false, TAG, ActivityMain.this);
            }

            @Override
            protected void onPostExecute(List<Rule> result) {
                if (running) {
                    if (adapter != null)
                        adapter.set(result);
                    if (menuSearch != null)
                        MenuItemCompat.collapseActionView(menuSearch);
                    if (swipeRefresh != null) {
                        refreshing = false;
                        swipeRefresh.setRefreshing(false);
                    }
                }
            }
        }.execute();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.main, menu);

        // Search
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

        if (!Util.hasValidFingerprint(TAG, this) || getIntentInvite(this).resolveActivity(getPackageManager()) == null)
            menu.removeItem(R.id.menu_invite);

        if (getIntentSupport().resolveActivity(getPackageManager()) == null)
            menu.removeItem(R.id.menu_support);

        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle item selection
        switch (item.getItemId()) {
            case R.id.menu_settings:
                startActivity(new Intent(this, ActivitySettings.class));
                return true;

            case R.id.menu_invite:
                startActivityForResult(getIntentInvite(this), REQUEST_INVITE);
                return true;

            case R.id.menu_support:
                startActivity(getIntentSupport());
                return true;

            case R.id.menu_about:
                menu_about();
                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    private void menu_about() {
        // Create view
        LayoutInflater inflater = LayoutInflater.from(this);
        View view = inflater.inflate(R.layout.about, null);
        TextView tvVersion = (TextView) view.findViewById(R.id.tvVersion);
        Button btnRate = (Button) view.findViewById(R.id.btnRate);
        final Button btnDonate = (Button) view.findViewById(R.id.btnDonate);
        final TextView tvThanks = (TextView) view.findViewById(R.id.tvThanks);
        TextView tvLicense = (TextView) view.findViewById(R.id.tvLicense);

        // Show version
        tvVersion.setText(Util.getSelfVersionName(this));
        if (!Util.hasValidFingerprint(TAG, this))
            tvVersion.setTextColor(Color.GRAY);

        // Handle license
        tvLicense.setMovementMethod(LinkMovementMethod.getInstance());

        // Handle logcat
        view.setOnClickListener(new View.OnClickListener() {
            private short tap = 0;

            @Override
            public void onClick(View view) {
                if (++tap == 7) {
                    tap = 0;
                    Util.sendLogcat(TAG, ActivityMain.this);
                }
            }
        });

        // Handle rate
        btnRate.setVisibility(getIntentRate(this).resolveActivity(getPackageManager()) == null ? View.GONE : View.VISIBLE);
        btnRate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(getIntentRate(ActivityMain.this));
            }
        });

        // In-app billing
        final IAB iab = new IAB(ActivityMain.this);

        // Handle donate
        btnDonate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    IntentSender sender = iab.getIntentSender();
                    if (sender == null) {
                        Log.i(TAG, "Donate");
                        Intent donate = new Intent(Intent.ACTION_VIEW);
                        donate.setData(Uri.parse("http://www.netguard.me/"));
                        startActivity(donate);
                    } else {
                        Log.i(TAG, "IAB donate");
                        startIntentSenderForResult(sender, REQUEST_IAB, new Intent(), 0, 0, 0);
                    }
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
            }
        });

        // Handle donated
        final BroadcastReceiver onIABPurchased = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                Log.i(TAG, "IAB donated");
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (running) {
                            btnDonate.setVisibility(View.GONE);
                            tvThanks.setVisibility(View.VISIBLE);
                        }
                    }
                });
            }
        };
        IntentFilter iff = new IntentFilter(IAB.ACTION_PURCHASED);
        LocalBroadcastManager.getInstance(this).registerReceiver(onIABPurchased, iff);

        // Show dialog
        dialogAbout = new AlertDialog.Builder(this)
                .setView(view)
                .setCancelable(true)
                .setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override
                    public void onDismiss(DialogInterface dialogInterface) {
                        if (running)
                            LocalBroadcastManager.getInstance(ActivityMain.this).unregisterReceiver(onIABPurchased);

                        iab.unbind();

                        dialogAbout = null;
                    }
                })
                .create();
        dialogAbout.show();

        // Connect to billing
        if (Util.hasValidFingerprint(TAG, this))
            iab.bind();
    }

    private static Intent getIntentInvite(Context context) {
        Intent intent = new Intent("com.google.android.gms.appinvite.ACTION_APP_INVITE");
        intent.setPackage("com.google.android.gms");
        intent.putExtra("com.google.android.gms.appinvite.TITLE", context.getString(R.string.menu_invite));
        intent.putExtra("com.google.android.gms.appinvite.MESSAGE", context.getString(R.string.msg_try));
        intent.putExtra("com.google.android.gms.appinvite.BUTTON_TEXT", context.getString(R.string.msg_try));
        // com.google.android.gms.appinvite.DEEP_LINK_URL
        return intent;
    }

    private static Intent getIntentRate(Context context) {
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + context.getPackageName()));
        if (intent.resolveActivity(context.getPackageManager()) == null)
            intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=" + context.getPackageName()));
        return intent;
    }

    private static Intent getIntentSupport() {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setData(Uri.parse("http://forum.xda-developers.com/showthread.php?t=3233012"));
        return intent;
    }

}