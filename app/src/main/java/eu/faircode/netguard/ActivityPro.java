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

    Copyright 2015-2017 by Marcel Bokhorst (M66B)
*/

import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.support.v4.app.NavUtils;
import android.support.v7.app.AppCompatActivity;
import android.text.Editable;
import android.text.TextWatcher;
import android.text.util.Linkify;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ActivityPro extends AppCompatActivity {
    private static final String TAG = "NetGuard.Pro";

    private IAB iab;

    // adb shell pm clear com.android.vending
    // android.test.purchased

    private static final int SKU_LOG_ID = 1;
    private static final int SKU_FILTER_ID = 2;
    private static final int SKU_NOTIFY_ID = 3;
    private static final int SKU_SPEED_ID = 4;
    private static final int SKU_THEME_ID = 5;
    private static final int SKU_PRO1_ID = 6;
    private static final int SKU_SUPPORT1_ID = 7;
    private static final int SKU_SUPPORT2_ID = 8;

    public static final String SKU_LOG = "log";
    public static final String SKU_FILTER = "filter";
    public static final String SKU_NOTIFY = "notify";
    public static final String SKU_SPEED = "speed";
    public static final String SKU_THEME = "theme";
    public static final String SKU_PRO1 = "pro1";
    public static final String SKU_SUPPORT1 = "support1";
    public static final String SKU_SUPPORT2 = "support2";
    public static final String SKU_DONATION = "donation";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.i(TAG, "Create");
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.pro);

        getSupportActionBar().setTitle(R.string.title_pro);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN);

        // Initial state
        updateState();

        TextView tvLogTitle = findViewById(R.id.tvLogTitle);
        TextView tvFilterTitle = findViewById(R.id.tvFilterTitle);
        TextView tvNotifyTitle = findViewById(R.id.tvNotifyTitle);
        TextView tvSpeedTitle = findViewById(R.id.tvSpeedTitle);
        TextView tvThemeTitle = findViewById(R.id.tvThemeTitle);
        TextView tvAllTitle = findViewById(R.id.tvAllTitle);
        TextView tvDev1Title = findViewById(R.id.tvDev1Title);
        TextView tvDev2Title = findViewById(R.id.tvDev2Title);

        Linkify.TransformFilter filter = new Linkify.TransformFilter() {
            @Override
            public String transformUrl(Matcher match, String url) {
                return "";
            }
        };

        Linkify.addLinks(tvLogTitle, Pattern.compile(".*"), "http://www.netguard.me/#" + SKU_LOG, null, filter);
        Linkify.addLinks(tvFilterTitle, Pattern.compile(".*"), "http://www.netguard.me/#" + SKU_FILTER, null, filter);
        Linkify.addLinks(tvNotifyTitle, Pattern.compile(".*"), "http://www.netguard.me/#" + SKU_NOTIFY, null, filter);
        Linkify.addLinks(tvSpeedTitle, Pattern.compile(".*"), "http://www.netguard.me/#" + SKU_SPEED, null, filter);
        Linkify.addLinks(tvThemeTitle, Pattern.compile(".*"), "http://www.netguard.me/#" + SKU_THEME, null, filter);
        Linkify.addLinks(tvAllTitle, Pattern.compile(".*"), "http://www.netguard.me/#" + SKU_PRO1, null, filter);
        Linkify.addLinks(tvDev1Title, Pattern.compile(".*"), "http://www.netguard.me/#" + SKU_SUPPORT1, null, filter);
        Linkify.addLinks(tvDev2Title, Pattern.compile(".*"), "http://www.netguard.me/#" + SKU_SUPPORT2, null, filter);

        String android_id = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
        String challenge = (Build.VERSION.SDK_INT < Build.VERSION_CODES.O ? Build.SERIAL : "O3" + android_id);
        String seed = (Build.VERSION.SDK_INT < Build.VERSION_CODES.O ? "NetGuard2" : "NetGuard3");

        // Challenge
        TextView tvChallenge = findViewById(R.id.tvChallenge);
        tvChallenge.setText(challenge);

        // Response
        try {
            final String response = Util.md5(challenge, seed);
            EditText etResponse = findViewById(R.id.etResponse);
            etResponse.addTextChangedListener(new TextWatcher() {
                @Override
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                    // Do nothing
                }

                @Override
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                    // Do nothing
                }

                @Override
                public void afterTextChanged(Editable editable) {
                    if (response.equals(editable.toString().toUpperCase())) {
                        IAB.setBought(SKU_DONATION, ActivityPro.this);
                        updateState();
                    }
                }
            });
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        try {
            iab = new IAB(new IAB.Delegate() {
                @Override
                public void onReady(final IAB iab) {
                    Log.i(TAG, "IAB ready");
                    try {
                        iab.updatePurchases();
                        updateState();

                        final Button btnLog = findViewById(R.id.btnLog);
                        final Button btnFilter = findViewById(R.id.btnFilter);
                        final Button btnNotify = findViewById(R.id.btnNotify);
                        final Button btnSpeed = findViewById(R.id.btnSpeed);
                        final Button btnTheme = findViewById(R.id.btnTheme);
                        final Button btnAll = findViewById(R.id.btnAll);
                        final Button btnDev1 = findViewById(R.id.btnDev1);
                        final Button btnDev2 = findViewById(R.id.btnDev2);

                        View.OnClickListener listener = new View.OnClickListener() {
                            @Override
                            public void onClick(View view) {
                                try {
                                    int id = 0;
                                    PendingIntent pi = null;
                                    if (view == btnLog) {
                                        id = SKU_LOG_ID;
                                        pi = iab.getBuyIntent(SKU_LOG, false);
                                    } else if (view == btnFilter) {
                                        id = SKU_FILTER_ID;
                                        pi = iab.getBuyIntent(SKU_FILTER, false);
                                    } else if (view == btnNotify) {
                                        id = SKU_NOTIFY_ID;
                                        pi = iab.getBuyIntent(SKU_NOTIFY, false);
                                    } else if (view == btnSpeed) {
                                        id = SKU_SPEED_ID;
                                        pi = iab.getBuyIntent(SKU_SPEED, false);
                                    } else if (view == btnTheme) {
                                        id = SKU_THEME_ID;
                                        pi = iab.getBuyIntent(SKU_THEME, false);
                                    } else if (view == btnAll) {
                                        id = SKU_PRO1_ID;
                                        pi = iab.getBuyIntent(SKU_PRO1, false);
                                    } else if (view == btnDev1) {
                                        id = SKU_SUPPORT1_ID;
                                        pi = iab.getBuyIntent(SKU_SUPPORT1, true);
                                    } else if (view == btnDev2) {
                                        id = SKU_SUPPORT2_ID;
                                        pi = iab.getBuyIntent(SKU_SUPPORT2, true);
                                    }

                                    if (id > 0 && pi != null)
                                        startIntentSenderForResult(pi.getIntentSender(), id, new Intent(), 0, 0, 0);
                                } catch (Throwable ex) {
                                    Log.i(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                                }
                            }
                        };

                        btnLog.setOnClickListener(listener);
                        btnFilter.setOnClickListener(listener);
                        btnNotify.setOnClickListener(listener);
                        btnSpeed.setOnClickListener(listener);
                        btnTheme.setOnClickListener(listener);
                        btnAll.setOnClickListener(listener);
                        btnDev1.setOnClickListener(listener);
                        btnDev2.setOnClickListener(listener);

                        btnLog.setEnabled(true);
                        btnFilter.setEnabled(true);
                        btnNotify.setEnabled(true);
                        btnSpeed.setEnabled(true);
                        btnTheme.setEnabled(true);
                        btnAll.setEnabled(true);
                        btnDev1.setEnabled(true);
                        btnDev2.setEnabled(true);

                    } catch (Throwable ex) {
                        Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    }
                }
            }, this);
            iab.bind();
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
    }

    @Override
    protected void onDestroy() {
        Log.i(TAG, "Destroy");
        iab.unbind();
        iab = null;
        super.onDestroy();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                Log.i(TAG, "Up");
                NavUtils.navigateUpFromSameTask(this);
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            switch (requestCode) {
                case SKU_LOG_ID:
                    IAB.setBought(SKU_LOG, this);
                    updateState();
                    break;
                case SKU_FILTER_ID:
                    IAB.setBought(SKU_FILTER, this);
                    updateState();
                    break;
                case SKU_NOTIFY_ID:
                    IAB.setBought(SKU_NOTIFY, this);
                    updateState();
                    break;
                case SKU_SPEED_ID:
                    IAB.setBought(SKU_SPEED, this);
                    updateState();
                    break;
                case SKU_THEME_ID:
                    IAB.setBought(SKU_THEME, this);
                    updateState();
                    break;
                case SKU_PRO1_ID:
                    IAB.setBought(SKU_PRO1, this);
                    updateState();
                    break;
                case SKU_SUPPORT1_ID:
                    IAB.setBought(SKU_SUPPORT1, this);
                    updateState();
                    break;
                case SKU_SUPPORT2_ID:
                    IAB.setBought(SKU_SUPPORT2, this);
                    updateState();
                    break;
            }
        }
    }

    private void updateState() {
        Button btnLog = findViewById(R.id.btnLog);
        Button btnFilter = findViewById(R.id.btnFilter);
        Button btnNotify = findViewById(R.id.btnNotify);
        Button btnSpeed = findViewById(R.id.btnSpeed);
        Button btnTheme = findViewById(R.id.btnTheme);
        Button btnAll = findViewById(R.id.btnAll);
        Button btnDev1 = findViewById(R.id.btnDev1);
        Button btnDev2 = findViewById(R.id.btnDev2);
        TextView tvLog = findViewById(R.id.tvLog);
        TextView tvFilter = findViewById(R.id.tvFilter);
        TextView tvNotify = findViewById(R.id.tvNotify);
        TextView tvSpeed = findViewById(R.id.tvSpeed);
        TextView tvTheme = findViewById(R.id.tvTheme);
        TextView tvAll = findViewById(R.id.tvAll);
        TextView tvDev1 = findViewById(R.id.tvDev1);
        TextView tvDev2 = findViewById(R.id.tvDev2);
        LinearLayout llChallenge = findViewById(R.id.llChallenge);

        TextView tvLogUnavailable = findViewById(R.id.tvLogUnavailable);
        TextView tvFilterUnavailable = findViewById(R.id.tvFilterUnavailable);

        boolean can = Util.canFilter(this);

        btnLog.setVisibility(IAB.isPurchased(SKU_LOG, this) || !can ? View.GONE : View.VISIBLE);
        btnFilter.setVisibility(IAB.isPurchased(SKU_FILTER, this) || !can ? View.GONE : View.VISIBLE);
        btnNotify.setVisibility(IAB.isPurchased(SKU_NOTIFY, this) ? View.GONE : View.VISIBLE);
        btnSpeed.setVisibility(IAB.isPurchased(SKU_SPEED, this) ? View.GONE : View.VISIBLE);
        btnTheme.setVisibility(IAB.isPurchased(SKU_THEME, this) ? View.GONE : View.VISIBLE);
        btnAll.setVisibility(IAB.isPurchased(SKU_PRO1, this) ? View.GONE : View.VISIBLE);
        btnDev1.setVisibility(IAB.isPurchased(SKU_SUPPORT1, this) ? View.GONE : View.VISIBLE);
        btnDev2.setVisibility(IAB.isPurchased(SKU_SUPPORT2, this) ? View.GONE : View.VISIBLE);

        tvLog.setVisibility(IAB.isPurchased(SKU_LOG, this) && can ? View.VISIBLE : View.GONE);
        tvFilter.setVisibility(IAB.isPurchased(SKU_FILTER, this) && can ? View.VISIBLE : View.GONE);
        tvNotify.setVisibility(IAB.isPurchased(SKU_NOTIFY, this) ? View.VISIBLE : View.GONE);
        tvSpeed.setVisibility(IAB.isPurchased(SKU_SPEED, this) ? View.VISIBLE : View.GONE);
        tvTheme.setVisibility(IAB.isPurchased(SKU_THEME, this) ? View.VISIBLE : View.GONE);
        tvAll.setVisibility(IAB.isPurchased(SKU_PRO1, this) ? View.VISIBLE : View.GONE);
        tvDev1.setVisibility(IAB.isPurchased(SKU_SUPPORT1, this) ? View.VISIBLE : View.GONE);
        tvDev2.setVisibility(IAB.isPurchased(SKU_SUPPORT2, this) ? View.VISIBLE : View.GONE);

        tvLogUnavailable.setVisibility(can ? View.GONE : View.VISIBLE);
        tvFilterUnavailable.setVisibility(can ? View.GONE : View.VISIBLE);

        llChallenge.setVisibility(
                IAB.isPurchased(SKU_DONATION, this) || Util.isPlayStoreInstall(this)
                        ? View.GONE : View.VISIBLE);
    }
}
