package eu.faircode.netguard;

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
import android.util.Xml;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import com.android.vending.billing.IInAppBillingService;

import org.json.JSONException;
import org.json.JSONObject;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xmlpull.v1.XmlSerializer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

public class ActivityMain extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Main";

    private boolean running = false;
    private ImageView ivInteractive;
    private ImageView ivWifi;
    private ImageView ivOther;
    private ImageView ivRoaming;
    private SwipeRefreshLayout swipeRefresh;
    private RuleAdapter adapter = null;
    private MenuItem menuSearch = null;
    private IInAppBillingService IABService = null;
    private AlertDialog dialogFirst = null;
    private AlertDialog dialogVpn = null;
    private AlertDialog dialogAbout = null;

    private static final int REQUEST_VPN = 1;
    private static final int REQUEST_IAB = 2;
    private static final int REQUEST_EXPORT = 3;
    private static final int REQUEST_IMPORT = 4;

    // adb shell pm clear com.android.vending
    private static final String SKU_DONATE = "donation";
    // private static final String SKU_DONATE = "android.test.purchased";
    private static final String ACTION_IAB = "eu.faircode.netguard.IAB";

    private static final Intent INTENT_VPN_SETTINGS = new Intent("android.net.vpn.SETTINGS");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.i(TAG, "Create");

        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        setTheme(prefs.getBoolean("dark_theme", false) ? R.style.AppThemeDark : R.style.AppTheme);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        running = true;
        boolean enabled = prefs.getBoolean("enabled", false);

        // Action bar
        View actionView = getLayoutInflater().inflate(R.layout.action, null);
        SwitchCompat swEnabled = (SwitchCompat) actionView.findViewById(R.id.swEnabled);
        ivInteractive = (ImageView) actionView.findViewById(R.id.ivInteractive);
        ivWifi = (ImageView) actionView.findViewById(R.id.ivWifi);
        ivOther = (ImageView) actionView.findViewById(R.id.ivOther);
        ivRoaming = (ImageView) actionView.findViewById(R.id.ivRoaming);
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
                                    public void onClick(DialogInterface dialogInterface, int i) {
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
                        public void onClick(DialogInterface dialogInterface, int i) {
                            if (running)
                                prefs.edit().putBoolean("initialized", true).apply();
                        }
                    })
                    .setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialogInterface, int i) {
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

    private BroadcastReceiver interactiveStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);

            ivInteractive.setVisibility(Intent.ACTION_SCREEN_ON.equals(intent.getAction()) ? View.VISIBLE : View.INVISIBLE);
        }
    };

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i(TAG, "Received " + intent);
            Util.logExtras(TAG, intent);

            ivWifi.setVisibility(View.GONE);
            ivOther.setVisibility(View.GONE);
            ivRoaming.setVisibility(View.GONE);

            if (Util.isWifiActive(context))
                ivWifi.setVisibility(View.VISIBLE);
            else if (Util.isRoaming(context))
                ivRoaming.setVisibility(View.VISIBLE);
            else
                ivOther.setVisibility(View.VISIBLE);
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
        }
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

        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        menu.findItem(R.id.menu_whitelist_wifi).setChecked(prefs.getBoolean("whitelist_wifi", true));
        menu.findItem(R.id.menu_whitelist_other).setChecked(prefs.getBoolean("whitelist_other", true));
        menu.findItem(R.id.menu_whitelist_roaming).setChecked(prefs.getBoolean("whitelist_roaming", true));
        menu.findItem(R.id.menu_system).setChecked(prefs.getBoolean("manage_system", false));
        menu.findItem(R.id.menu_export).setEnabled(getIntentCreateDocument().resolveActivity(getPackageManager()) != null);
        menu.findItem(R.id.menu_import).setEnabled(getIntentOpenDocument().resolveActivity(getPackageManager()) != null);
        menu.findItem(R.id.menu_theme).setChecked(prefs.getBoolean("dark_theme", false));
        menu.findItem(R.id.menu_vpn_settings).setEnabled(INTENT_VPN_SETTINGS.resolveActivity(getPackageManager()) != null);
        menu.findItem(R.id.menu_support).setEnabled(getIntentSupport().resolveActivity(getPackageManager()) != null);

        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Handle item selection
        switch (item.getItemId()) {
            case R.id.menu_whitelist_wifi:
                menu_whitelist_wifi(prefs);
                return true;

            case R.id.menu_whitelist_other:
                menu_whitelist_other(prefs);
                return true;

            case R.id.menu_whitelist_roaming:
                menu_whitelist_roaming(prefs);
                return true;

            case R.id.menu_system:
                menu_system(prefs);
                return true;

            case R.id.menu_export:
                startActivityForResult(getIntentCreateDocument(), REQUEST_EXPORT);
                return true;

            case R.id.menu_import:
                startActivityForResult(getIntentOpenDocument(), REQUEST_IMPORT);
                return true;

            case R.id.menu_theme:
                menu_theme(prefs);
                return true;

            case R.id.menu_vpn_settings:
                startActivity(INTENT_VPN_SETTINGS);
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

    private void menu_whitelist_wifi(SharedPreferences prefs) {
        prefs.edit().putBoolean("whitelist_wifi", !prefs.getBoolean("whitelist_wifi", true)).apply();
        updateApplicationList();
        SinkholeService.reload("wifi", this);
    }

    private void menu_whitelist_other(SharedPreferences prefs) {
        prefs.edit().putBoolean("whitelist_other", !prefs.getBoolean("whitelist_other", true)).apply();
        updateApplicationList();
        SinkholeService.reload("other", this);
    }

    private void menu_whitelist_roaming(SharedPreferences prefs) {
        prefs.edit().putBoolean("whitelist_roaming", !prefs.getBoolean("whitelist_roaming", true)).apply();
        updateApplicationList();
        SinkholeService.reload("other", this);
    }

    private void menu_system(SharedPreferences prefs) {
        prefs.edit().putBoolean("manage_system", !prefs.getBoolean("manage_system", false)).apply();
        updateApplicationList();
        SinkholeService.reload(null, this);
    }

    private void menu_theme(SharedPreferences prefs) {
        prefs.edit().putBoolean("dark_theme", !prefs.getBoolean("dark_theme", false)).apply();
        recreate();
    }

    private void menu_about() {
        // Create view
        LayoutInflater inflater = LayoutInflater.from(this);
        View view = inflater.inflate(R.layout.about, null);
        TextView tvVersion = (TextView) view.findViewById(R.id.tvVersion);
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
                boolean purchased = (result instanceof Boolean && (Boolean) result);
                btnDonate.setVisibility(purchased ? View.GONE : View.VISIBLE);
                tvThanks.setVisibility(purchased ? View.VISIBLE : View.GONE);
            }
        }.execute();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, final Intent data) {
        Log.i(TAG, "onActivityResult request=" + requestCode + " result=" + requestCode + " ok=" + (resultCode == RESULT_OK));
        Util.logExtras(TAG, data);

        if (requestCode == REQUEST_VPN) {
            // Update enabled state
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean("enabled", resultCode == RESULT_OK).apply();

            // Start service
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
            }

        } else if (requestCode == REQUEST_EXPORT) {
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
                    Toast.makeText(ActivityMain.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                else
                    Toast.makeText(ActivityMain.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
        }.execute();
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
                    SinkholeService.reload(null, ActivityMain.this);
                    recreate();
                    Toast.makeText(ActivityMain.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                } else
                    Toast.makeText(ActivityMain.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
        }.execute();
    }

    private static Intent getIntentSupport() {
        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setData(Uri.parse("http://forum.xda-developers.com/showthread.php?t=3233012"));
        return intent;
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

    private void xmlExport(OutputStream out) throws IOException {
        XmlSerializer serializer = Xml.newSerializer();
        serializer.setOutput(out, "UTF-8");
        serializer.startDocument(null, Boolean.valueOf(true));
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

        serializer.startTag(null, "unused");
        xmlExport(getSharedPreferences("unused", Context.MODE_PRIVATE), serializer);
        serializer.endTag(null, "unused");

        serializer.endTag(null, "netguard");
        serializer.endDocument();
        serializer.flush();
    }

    private void xmlExport(SharedPreferences prefs, XmlSerializer serializer) throws IOException {
        Map<String, ?> settings = prefs.getAll();
        for (String key : settings.keySet()) {
            Object value = settings.get(key);
            if (value instanceof Boolean) {
                serializer.startTag(null, "setting");
                serializer.attribute(null, "key", key);
                serializer.attribute(null, "type", "boolean");
                serializer.attribute(null, "value", value.toString());
                serializer.endTag(null, "setting");
            } else
                Log.e(TAG, "Unknown key=" + key);
        }
    }

    private void xmlImport(InputStream in) throws IOException, SAXException, ParserConfigurationException {
        XMLReader reader = SAXParserFactory.newInstance().newSAXParser().getXMLReader();
        XmlImportHandler handler = new XmlImportHandler();
        reader.setContentHandler(handler);
        reader.parse(new InputSource(in));

        xmlImport(handler.application, PreferenceManager.getDefaultSharedPreferences(this));
        xmlImport(handler.wifi, getSharedPreferences("wifi", Context.MODE_PRIVATE));
        xmlImport(handler.mobile, getSharedPreferences("other", Context.MODE_PRIVATE));
        xmlImport(handler.unused, getSharedPreferences("unused", Context.MODE_PRIVATE));
    }

    private void xmlImport(Map<String, Object> settings, SharedPreferences prefs) {
        SharedPreferences.Editor editor = prefs.edit();

        for (String key : prefs.getAll().keySet())
            editor.remove(key);

        for (String key : settings.keySet()) {
            Object value = settings.get(key);
            if (value instanceof Boolean)
                editor.putBoolean(key, (Boolean) value);
            else
                Log.e(TAG, "Unknown type=" + value.getClass());
        }

        editor.apply();
    }

    private class XmlImportHandler extends DefaultHandler {
        public Map<String, Object> application = new HashMap<>();
        public Map<String, Object> wifi = new HashMap<>();
        public Map<String, Object> mobile = new HashMap<>();
        public Map<String, Object> unused = new HashMap<>();
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

            else if (qName.equals("setting")) {
                String key = attributes.getValue("key");
                String type = attributes.getValue("type");
                String value = attributes.getValue("value");

                if (current == null)
                    Log.e(TAG, "No current key=" + key);
                else {
                    if ("boolean".equals(type))
                        current.put(key, Boolean.parseBoolean(value));
                    else
                        Log.e(TAG, "Unknown type key=" + key);
                }

            } else
                Log.e(TAG, "Unknown element qname=" + qName);
        }
    }
}