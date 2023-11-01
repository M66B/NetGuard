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

    Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/

import android.app.PendingIntent;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Paint;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.NavUtils;

import static android.content.ClipDescription.MIMETYPE_TEXT_PLAIN;

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

        tvLogTitle.setPaintFlags(tvLogTitle.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
        tvFilterTitle.setPaintFlags(tvLogTitle.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
        tvNotifyTitle.setPaintFlags(tvLogTitle.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
        tvSpeedTitle.setPaintFlags(tvLogTitle.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
        tvThemeTitle.setPaintFlags(tvLogTitle.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
        tvAllTitle.setPaintFlags(tvLogTitle.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
        tvDev1Title.setPaintFlags(tvLogTitle.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
        tvDev2Title.setPaintFlags(tvLogTitle.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);

        View.OnClickListener listener = new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String sku;
                switch (view.getId()) {
                    case R.id.tvLogTitle:
                        sku = SKU_LOG;
                        break;
                    case R.id.tvFilterTitle:
                        sku = SKU_FILTER;
                        break;
                    case R.id.tvNotifyTitle:
                        sku = SKU_NOTIFY;
                        break;
                    case R.id.tvSpeedTitle:
                        sku = SKU_SPEED;
                        break;
                    case R.id.tvThemeTitle:
                        sku = SKU_THEME;
                        break;
                    case R.id.tvAllTitle:
                        sku = SKU_PRO1;
                        break;
                    case R.id.tvDev1Title:
                        sku = SKU_SUPPORT1;
                        break;
                    case R.id.tvDev2Title:
                        sku = SKU_SUPPORT2;
                        break;
                    default:
                        sku = SKU_PRO1;
                        break;
                }

                Intent intent = new Intent(Intent.ACTION_VIEW);
                intent.setData(Uri.parse("http://www.netguard.me/#" + sku));
                if (intent.resolveActivity(getPackageManager()) != null)
                    startActivity(intent);
            }
        };

        tvLogTitle.setOnClickListener(listener);
        tvFilterTitle.setOnClickListener(listener);
        tvNotifyTitle.setOnClickListener(listener);
        tvSpeedTitle.setOnClickListener(listener);
        tvThemeTitle.setOnClickListener(listener);
        tvAllTitle.setOnClickListener(listener);
        tvDev1Title.setOnClickListener(listener);
        tvDev2Title.setOnClickListener(listener);

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
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.pro, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                Log.i(TAG, "Up");
                NavUtils.navigateUpFromSameTask(this);
                return true;
            case R.id.menu_challenge:
                menu_challenge();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        if (Util.isPlayStoreInstall(this))
            menu.removeItem(R.id.menu_challenge);

        return super.onPrepareOptionsMenu(menu);
    }

    private void menu_challenge() {
        if (IAB.isPurchased(SKU_DONATION, this)) {
            Toast.makeText(this, getString(R.string.title_pro_already), Toast.LENGTH_LONG).show();
            return;
        }

        LayoutInflater inflater = LayoutInflater.from(this);
        View view = inflater.inflate(R.layout.challenge, null, false);

        final AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(view)
                .setCancelable(true)
                .create();

        String android_id = Settings.Secure.getString(getContentResolver(), Settings.Secure.ANDROID_ID);
        final String challenge = (Build.VERSION.SDK_INT < Build.VERSION_CODES.O ? Build.SERIAL : "O3" + android_id);
        String seed = (Build.VERSION.SDK_INT < Build.VERSION_CODES.O ? "NetGuard2" : "NetGuard3");

        // Challenge
        TextView tvChallenge = view.findViewById(R.id.tvChallenge);
        tvChallenge.setText(challenge);

        ImageButton ibCopy = view.findViewById(R.id.ibCopy);
        ibCopy.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText(getString(R.string.title_pro_challenge), challenge);
                clipboard.setPrimaryClip(clip);
                Toast.makeText(ActivityPro.this, android.R.string.copy, Toast.LENGTH_LONG).show();
            }
        });

        // Response
        final EditText etResponse = view.findViewById(R.id.etResponse);
        try {
            final String response = Util.md5(challenge, seed);
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
                        dialog.dismiss();
                        invalidateOptionsMenu();
                        updateState();
                    }
                }
            });
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }

        ImageButton ibPaste = view.findViewById(R.id.ibPaste);
        ibPaste.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (clipboard != null &&
                        clipboard.hasPrimaryClip() &&
                        clipboard.getPrimaryClipDescription().hasMimeType(MIMETYPE_TEXT_PLAIN)) {
                    ClipData.Item item = clipboard.getPrimaryClip().getItemAt(0);
                    etResponse.setText(item.getText().toString());
                }
            }
        });

        dialog.show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
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
    }
}
