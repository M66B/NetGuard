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

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class ActivityPro extends AppCompatActivity {
    private static final String TAG = "NetGuard.Pro";

    private IAB iab;

    // adb shell pm clear com.android.vending
    public static final String SKU_SELECT = "select";
    public static final String SKU_DEFAULTS = "defaults";
    public static final String SKU_THEME = "theme";
    public static final String SKU_SPEED = "speed";
    public static final String SKU_BACKUP = "backup";
    public static final String SKU_DONATION = "donation";
    //public static final String SKU_DEFAULTS = "android.test.purchased";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        setTheme(prefs.getBoolean("dark_theme", false) ? R.style.AppThemeDark : R.style.AppTheme);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.pro);

        getSupportActionBar().setTitle(R.string.title_pro);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        updateState();

        try {
            iab = new IAB(new IAB.Delegate() {
                @Override
                public void onReady(final IAB iab) {
                    Log.i(TAG, "IAB ready");
                    try {
                        iab.isPurchased(SKU_DONATION);

                        final Button btnSelect = (Button) findViewById(R.id.btnSelect);
                        final Button btnDefaults = (Button) findViewById(R.id.btnDefaults);
                        final Button btnTheme = (Button) findViewById(R.id.btnTheme);
                        final Button btnSpeed = (Button) findViewById(R.id.btnSpeed);
                        final Button btnBackup = (Button) findViewById(R.id.btnBackup);

                        View.OnClickListener listener = new View.OnClickListener() {
                            @Override
                            public void onClick(View view) {
                                try {
                                    if (view == btnSelect)
                                        startIntentSenderForResult(iab.getBuyIntent(SKU_SELECT).getIntentSender(), view.getId(), new Intent(), 0, 0, 0);
                                    else if (view == btnDefaults)
                                        startIntentSenderForResult(iab.getBuyIntent(SKU_DEFAULTS).getIntentSender(), view.getId(), new Intent(), 0, 0, 0);
                                    else if (view == btnTheme)
                                        startIntentSenderForResult(iab.getBuyIntent(SKU_THEME).getIntentSender(), view.getId(), new Intent(), 0, 0, 0);
                                    else if (view == btnSpeed)
                                        startIntentSenderForResult(iab.getBuyIntent(SKU_SPEED).getIntentSender(), view.getId(), new Intent(), 0, 0, 0);
                                    else if (view == btnBackup)
                                        startIntentSenderForResult(iab.getBuyIntent(SKU_BACKUP).getIntentSender(), view.getId(), new Intent(), 0, 0, 0);
                                } catch (Throwable ex) {
                                    Log.i(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                                    Util.sendCrashReport(ex, ActivityPro.this);
                                }
                            }
                        };

                        btnSelect.setOnClickListener(listener);
                        btnDefaults.setOnClickListener(listener);
                        btnTheme.setOnClickListener(listener);
                        btnSpeed.setOnClickListener(listener);
                        btnBackup.setOnClickListener(listener);

                        btnSelect.setEnabled(true);
                        btnDefaults.setEnabled(true);
                        btnTheme.setEnabled(true);
                        btnSpeed.setEnabled(true);
                        btnBackup.setEnabled(true);

                    } catch (Throwable ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
                }
            }, this);
            iab.bind();
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            Util.sendCrashReport(ex, ActivityPro.this);
        }
    }

    @Override
    protected void onDestroy() {
        iab.unbind();
        super.onDestroy();
    }

    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                finish();
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            switch (requestCode) {
                case R.id.btnSelect:
                    IAB.setBought(SKU_SELECT, this);
                    updateState();
                    break;
                case R.id.btnDefaults:
                    IAB.setBought(SKU_DEFAULTS, this);
                    updateState();
                    break;
                case R.id.btnTheme:
                    IAB.setBought(SKU_THEME, this);
                    updateState();
                    break;
                case R.id.btnSpeed:
                    IAB.setBought(SKU_SPEED, this);
                    updateState();
                    break;
                case R.id.btnBackup:
                    IAB.setBought(SKU_BACKUP, this);
                    updateState();
                    break;
            }
        }
    }

    private void updateState() {
        Button btnSelect = (Button) findViewById(R.id.btnSelect);
        Button btnDefaults = (Button) findViewById(R.id.btnDefaults);
        Button btnTheme = (Button) findViewById(R.id.btnTheme);
        Button btnSpeed = (Button) findViewById(R.id.btnSpeed);
        Button btnBackup = (Button) findViewById(R.id.btnBackup);
        TextView tvSelect = (TextView) findViewById(R.id.tvSelect);
        TextView tvDefaults = (TextView) findViewById(R.id.tvDefaults);
        TextView tvTheme = (TextView) findViewById(R.id.tvTheme);
        TextView tvSpeed = (TextView) findViewById(R.id.tvSpeed);
        TextView tvBackup = (TextView) findViewById(R.id.tvBackup);

        btnSelect.setVisibility(IAB.isPurchased(SKU_SELECT, this) ? View.GONE : View.VISIBLE);
        btnDefaults.setVisibility(IAB.isPurchased(SKU_DEFAULTS, this) ? View.GONE : View.VISIBLE);
        btnTheme.setVisibility(IAB.isPurchased(SKU_THEME, this) ? View.GONE : View.VISIBLE);
        btnSpeed.setVisibility(IAB.isPurchased(SKU_SPEED, this) ? View.GONE : View.VISIBLE);
        btnBackup.setVisibility(IAB.isPurchased(SKU_BACKUP, this) ? View.GONE : View.VISIBLE);

        tvSelect.setVisibility(IAB.isPurchased(SKU_SELECT, this) ? View.VISIBLE : View.GONE);
        tvDefaults.setVisibility(IAB.isPurchased(SKU_DEFAULTS, this) ? View.VISIBLE : View.GONE);
        tvTheme.setVisibility(IAB.isPurchased(SKU_THEME, this) ? View.VISIBLE : View.GONE);
        tvSpeed.setVisibility(IAB.isPurchased(SKU_SPEED, this) ? View.VISIBLE : View.GONE);
        tvBackup.setVisibility(IAB.isPurchased(SKU_BACKUP, this) ? View.VISIBLE : View.GONE);
    }
}
