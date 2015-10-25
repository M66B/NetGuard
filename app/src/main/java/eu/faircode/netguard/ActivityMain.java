package eu.faircode.netguard;

import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;

import java.util.List;

public class ActivityMain extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Main";

    private boolean running = false;
    private RuleAdapter adapter = null;

    private static final int REQUEST_VPN = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.i(TAG, "Create");
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        running = true;

        // Action bar
        View view = getLayoutInflater().inflate(R.layout.actionbar, null);
        getSupportActionBar().setDisplayShowCustomEnabled(true);
        getSupportActionBar().setCustomView(view);

        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // On/off switch
        Switch swEnabled = (Switch) view.findViewById(R.id.swEnabled);
        swEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                if (isChecked) {
                    Log.i(TAG, "On");
                    Intent intent = VpnService.prepare(ActivityMain.this);
                    if (intent == null) {
                        Log.e(TAG, "Prepare done");
                        onActivityResult(REQUEST_VPN, RESULT_OK, null);
                    } else {
                        Log.i(TAG, "Start intent=" + intent);
                        startActivityForResult(intent, REQUEST_VPN);
                    }
                } else {
                    Log.i(TAG, "Off");
                    prefs.edit().putBoolean("enabled", false).apply();
                    Intent intent = new Intent(ActivityMain.this, BlackHoleService.class);
                    intent.putExtra(BlackHoleService.EXTRA_COMMAND, BlackHoleService.Command.stop);
                    startService(intent);
                }
            }
        });
        swEnabled.setChecked(prefs.getBoolean("enabled", false));

        // Listen for external enabled changes
        prefs.registerOnSharedPreferenceChangeListener(this);

        // Package list
        final RecyclerView rvApplication = (RecyclerView) findViewById(R.id.rvApplication);
        rvApplication.setHasFixedSize(true);
        rvApplication.setLayoutManager(new LinearLayoutManager(this));

        new AsyncTask<Object, Object, List<Rule>>() {
            @Override
            protected List<Rule> doInBackground(Object... arg) {
                return Rule.getRules(ActivityMain.this);
            }

            @Override
            protected void onPostExecute(List<Rule> result) {
                if (running) {
                    adapter = new RuleAdapter(result);
                    rvApplication.setAdapter(adapter);
                }
            }
        }.execute();
    }

    @Override
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        Log.i(TAG, "Changed pref=" + name);
        if ("enabled".equals(name)) {
            boolean enabled = prefs.getBoolean(name, false);
            Switch swEnabled = (Switch) getSupportActionBar().getCustomView().findViewById(R.id.swEnabled);
            if (swEnabled.isChecked() != enabled)
                swEnabled.setChecked(enabled);
        }
    }

    @Override
    public void onDestroy() {
        Log.i(TAG, "Destroy");
        running = false;
        PreferenceManager.getDefaultSharedPreferences(this).unregisterOnSharedPreferenceChangeListener(this);
        super.onDestroy();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle item selection
        switch (item.getItemId()) {
            case R.id.menu_vpn_settings:
                Intent intent = new Intent("android.net.vpn.SETTINGS");
                intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                if (intent.resolveActivity(getPackageManager()) != null)
                    startActivity(intent);
                else
                    Log.w(TAG, intent + " not available");
                return true;

            case R.id.menu_about:
                LayoutInflater inflater = LayoutInflater.from(this);
                View view = inflater.inflate(R.layout.about, null);
                TextView tvVersion = (TextView) view.findViewById(R.id.tvVersion);
                tvVersion.setText(Util.getSelfVersionName(this));
                AlertDialog dialog = new AlertDialog.Builder(this)
                        .setView(view)
                        .setCancelable(true).create();
                dialog.show();
                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_VPN) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean("enabled", resultCode == RESULT_OK).apply();

            if (resultCode == RESULT_OK) {
                Intent intent = new Intent(ActivityMain.this, BlackHoleService.class);
                intent.putExtra(BlackHoleService.EXTRA_COMMAND, BlackHoleService.Command.start);
                startService(intent);
            }
        } else
            super.onActivityResult(requestCode, resultCode, data);
    }
}
