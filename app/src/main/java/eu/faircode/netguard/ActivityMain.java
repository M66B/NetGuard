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
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.IntentSender;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.AsyncTask;
import android.os.IBinder;
import android.os.RemoteException;
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
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.android.vending.billing.IInAppBillingService;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class ActivityMain extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Main";

    private boolean running = false;
    private View actionView;
    private LinearLayout llIndicators;
    private ImageView ivInteractive;
    private ImageView ivNetwork;
    private ImageView ivMetered;
    private SwipeRefreshLayout swipeRefresh;
    private RuleAdapter adapter = null;
    private MenuItem menuSearch = null;
    private IInAppBillingService IABService = null;
    private AlertDialog dialogFirst = null;
    private AlertDialog dialogVpn = null;
    private AlertDialog dialogAbout = null;

    private static final int REQUEST_VPN = 1;
    private static final int REQUEST_IAB = 2;
    private static final int REQUEST_INVITE = 3;

    // adb shell pm clear com.android.vending
    private static final String SKU_DONATE = "donation";
    // private static final String SKU_DONATE = "android.test.purchased";
    private static final String ACTION_IAB = "eu.faircode.netguard.IAB";

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
        actionView = getLayoutInflater().inflate(R.layout.action, null);
        SwitchCompat swEnabled = (SwitchCompat) actionView.findViewById(R.id.swEnabled);
        llIndicators = (LinearLayout) actionView.findViewById(R.id.llIndicators);
        ivInteractive = (ImageView) actionView.findViewById(R.id.ivInteractive);
        ivNetwork = (ImageView) actionView.findViewById(R.id.ivNetwork);
        ivMetered = (ImageView) actionView.findViewById(R.id.ivMetered);
        getSupportActionBar().setDisplayShowCustomEnabled(true);
        getSupportActionBar().setCustomView(actionView);

        // On/off switch
        swEnabled.setChecked(enabled);
        swEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
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

        // Indicators
        llIndicators.setVisibility(Util.isDebuggable(this) ? View.VISIBLE : View.GONE);

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

        // Listen for interactive state changes
        IntentFilter ifInteractive = new IntentFilter();
        ifInteractive.addAction(Intent.ACTION_SCREEN_ON);
        ifInteractive.addAction(Intent.ACTION_SCREEN_OFF);
        registerReceiver(interactiveStateReceiver, ifInteractive);

        // Listen for connectivity updates
        IntentFilter ifConnectivity = new IntentFilter();
        ifConnectivity.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, ifConnectivity);

        // Listen for added/removed applications
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(Intent.ACTION_PACKAGE_ADDED);
        intentFilter.addAction(Intent.ACTION_PACKAGE_REMOVED);
        intentFilter.addDataScheme("package");
        registerReceiver(packageChangedReceiver, intentFilter);

        // Connect to billing
        if (Util.hasValidFingerprint(TAG, this)) {
            Intent serviceIntent = new Intent("com.android.vending.billing.InAppBillingService.BIND");
            serviceIntent.setPackage("com.android.vending");
            bindService(serviceIntent, IABConnection, Context.BIND_AUTO_CREATE);
        }

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

        unregisterReceiver(interactiveStateReceiver);
        unregisterReceiver(connectivityChangedReceiver);
        unregisterReceiver(packageChangedReceiver);

        if (IABService != null) {
            unbindService(IABConnection);
            IABService = null;
        }

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
                Intent intent = new Intent(ACTION_IAB);
                LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
            } else {
                int response = (data == null ? -1 : data.getIntExtra("RESPONSE_CODE", -1));
                Log.i(TAG, "IAB response=" + getIABResult(response));

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
                "whitelist_roaming".equals(name) ||
                "manage_system".equals(name) ||
                "imported".equals(name))
            updateApplicationList();

        else if ("dark_theme".equals(name))
            recreate();

        else if ("indicators".equals(name))
            llIndicators.setVisibility(prefs.getBoolean(name, false) ? View.VISIBLE : View.GONE);
    }

    private BroadcastReceiver interactiveStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);

            ivInteractive.setVisibility(Intent.ACTION_SCREEN_ON.equals(intent.getAction()) ? View.VISIBLE : View.INVISIBLE);
            actionView.postInvalidate();
        }
    };

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            int networkType = intent.getIntExtra(ConnectivityManager.EXTRA_NETWORK_TYPE, ConnectivityManager.TYPE_DUMMY);
            if (networkType == ConnectivityManager.TYPE_VPN)
                return;

            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);

            ivNetwork.setVisibility(View.VISIBLE);
            ivMetered.setVisibility(View.VISIBLE);

            if (Util.isWifiActive(context))
                ivNetwork.setImageLevel(1);
            else {
                if (Util.isRoaming(context))
                    ivNetwork.setImageLevel(3);
                else
                    ivNetwork.setImageLevel(2);
            }
            ivMetered.setImageLevel(Util.isMetered(context) ? 1 : 0);

            actionView.postInvalidate();
        }
    };

    private BroadcastReceiver packageChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);
            updateApplicationList();
        }
    };

    private ServiceConnection IABConnection = new ServiceConnection() {
        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.i(TAG, "IAB disconnected");
            IABService = null;
        }

        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            Log.i(TAG, "IAB connected");
            IABService = IInAppBillingService.Stub.asInterface(service);
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

        // Handle license
        tvLicense.setMovementMethod(LinkMovementMethod.getInstance());

        // Handle logcat
        if (Util.hasValidFingerprint(TAG, this))
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

        // Handle donate
        btnDonate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new AsyncTask<Object, Object, Object>() {
                    @Override
                    protected void onPreExecute() {
                        btnDonate.setEnabled(false);
                    }

                    @Override
                    protected Object doInBackground(Object... objects) {
                        try {
                            if (IABService == null || !IABisAvailable(SKU_DONATE, IABService, ActivityMain.this))
                                return false;
                            if (IABService == null || IABisPurchased(SKU_DONATE, IABService, ActivityMain.this))
                                return false;
                            return true;
                        } catch (Throwable ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                            return ex;
                        }
                    }

                    @Override
                    protected void onPostExecute(Object result) {
                        if (running)
                            try {
                                if (result instanceof Boolean && (Boolean) result && IABService != null) {
                                    IntentSender sender = IABgetIntent(SKU_DONATE, IABService, ActivityMain.this);
                                    startIntentSenderForResult(sender, REQUEST_IAB, new Intent(), 0, 0, 0);
                                } else {
                                    Intent donate = new Intent(Intent.ACTION_VIEW);
                                    donate.setData(Uri.parse("http://www.netguard.me/"));
                                    startActivity(donate);
                                }
                            } catch (Throwable ex) {
                                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                                Toast.makeText(ActivityMain.this, result.toString(), Toast.LENGTH_LONG).show();
                            } finally {
                                btnDonate.setEnabled(true);
                            }
                    }
                }.execute();
            }
        });

        // Handle donated
        final BroadcastReceiver onIABsuccess = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                btnDonate.setVisibility(View.GONE);
                tvThanks.setVisibility(View.VISIBLE);
            }
        };
        IntentFilter iff = new IntentFilter(ACTION_IAB);
        LocalBroadcastManager.getInstance(this).registerReceiver(onIABsuccess, iff);

        // Show dialog
        dialogAbout = new AlertDialog.Builder(this)
                .setView(view)
                .setCancelable(true)
                .setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override
                    public void onDismiss(DialogInterface dialogInterface) {
                        if (running)
                            LocalBroadcastManager.getInstance(ActivityMain.this).unregisterReceiver(onIABsuccess);
                        dialogAbout = null;
                    }
                })
                .create();
        dialogAbout.show();

        // Check if IAB purchased
        new AsyncTask<Object, Object, Object>() {
            @Override
            protected Object doInBackground(Object... objects) {
                try {
                    return (IABService != null && IABisPurchased(SKU_DONATE, IABService, ActivityMain.this));
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    return ex;
                }
            }

            @Override
            protected void onPostExecute(Object result) {
                if (running) {
                    boolean purchased = (result instanceof Boolean && (Boolean) result);
                    btnDonate.setVisibility(purchased ? View.GONE : View.VISIBLE);
                    tvThanks.setVisibility(purchased ? View.VISIBLE : View.GONE);
                }
            }
        }.execute();
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

    private static boolean IABisAvailable(String sku, IInAppBillingService service, Context context) throws RemoteException, JSONException {
        ArrayList<String> skuList = new ArrayList<>();
        skuList.add(sku);
        Bundle query = new Bundle();
        query.putStringArrayList("ITEM_ID_LIST", skuList);
        Bundle bundle = service.getSkuDetails(3, context.getPackageName(), "inapp", query);
        Log.i(TAG, "IAB.getSkuDetails");
        Util.logBundle(TAG, bundle);
        int response = (bundle == null ? -1 : bundle.getInt("RESPONSE_CODE", -1));
        Log.i(TAG, "IAB response=" + getIABResult(response));
        if (response != 0)
            return false;

        // Check available SKUs
        boolean found = false;
        ArrayList<String> details = bundle.getStringArrayList("DETAILS_LIST");
        if (details != null)
            for (String item : details) {
                JSONObject object = new JSONObject(item);
                if (sku.equals(object.getString("productId"))) {
                    found = true;
                    break;
                }
            }
        Log.i(TAG, sku + "=" + found);

        return found;
    }

    private static boolean IABisPurchased(String sku, IInAppBillingService service, Context context) throws RemoteException {
        // Get purchases
        Bundle bundle = service.getPurchases(3, context.getPackageName(), "inapp", null);
        Log.i(TAG, "IAB.getPurchases");
        Util.logBundle(TAG, bundle);
        int response = (bundle == null ? -1 : bundle.getInt("RESPONSE_CODE", -1));
        Log.i(TAG, "IAB response=" + getIABResult(response));
        if (response != 0)
            return false;

        // Check purchases
        ArrayList<String> skus = bundle.getStringArrayList("INAPP_PURCHASE_ITEM_LIST");
        return (skus != null && skus.contains(sku));
    }

    private static IntentSender IABgetIntent(String sku, IInAppBillingService service, Context context) throws RemoteException {
        Bundle bundle = service.getBuyIntent(3, context.getPackageName(), sku, "inapp", "");
        Log.i(TAG, "IAB.getBuyIntent");
        Util.logBundle(TAG, bundle);
        int response = (bundle == null ? -1 : bundle.getInt("RESPONSE_CODE", -1));
        Log.i(TAG, "IAB response=" + getIABResult(response));
        if (response != 0 || !bundle.containsKey("BUY_INTENT"))
            return null;
        PendingIntent pi = bundle.getParcelable("BUY_INTENT");
        return (pi == null ? null : pi.getIntentSender());
    }

    private static String getIABResult(int responseCode) {
        switch (responseCode) {
            case 0:
                return "OK";
            case 1:
                return "USER_CANCELED";
            case 2:
                return "SERVICE_UNAVAILABLE";
            case 3:
                return "BILLING_UNAVAILABLE";
            case 4:
                return "ITEM_UNAVAILABLE";
            case 5:
                return "DEVELOPER_ERROR";
            case 6:
                return "ERROR";
            case 7:
                return "ITEM_ALREADY_OWNED";
            case 8:
                return "ITEM_NOT_OWNED";
            default:
                return Integer.toString(responseCode);
        }
    }
}