package eu.faircode.netguard;

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
import android.view.View;
import android.widget.CompoundButton;
import android.widget.Switch;

import java.util.List;

public class ActivityMain extends AppCompatActivity {
    private static final String TAG = "NetGuard.Main";
    private static final int REQUEST_VPN = 1;

    private boolean running = false;
    private RuleAdapter adapter = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        running = true;

        View view = getLayoutInflater().inflate(R.layout.actionbar, null);
        getSupportActionBar().setDisplayShowCustomEnabled(true);
        getSupportActionBar().setCustomView(view);

        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // On/off switch
        Switch swEnabled = (Switch) view.findViewById(R.id.swEnabled);
        swEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                prefs.edit().putBoolean("enabled", isChecked).apply();

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
                    Intent intent = new Intent(ActivityMain.this, BlackHoleService.class);
                    intent.putExtra(BlackHoleService.EXTRA_START, false);
                    Log.i(TAG, "Stop service=" + intent);
                    startService(intent);
                }
            }
        });
        swEnabled.setChecked(prefs.getBoolean("enabled", false));

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
    public void onDestroy() {
        super.onDestroy();
        running = false;
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) {
                Intent intent = new Intent(this, BlackHoleService.class);
                intent.putExtra(BlackHoleService.EXTRA_START, true);
                Log.i(TAG, "Start service=" + intent);
                startService(intent);
            }
        } else
            super.onActivityResult(requestCode, resultCode, data);
    }
}
