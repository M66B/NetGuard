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

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.TypedArray;
import android.database.Cursor;
import android.graphics.Color;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.preference.PreferenceManager;
import android.support.v4.app.NotificationManagerCompat;
import android.support.v4.content.ContextCompat;
import android.support.v4.graphics.drawable.DrawableCompat;
import android.support.v4.widget.CompoundButtonCompat;
import android.support.v7.widget.RecyclerView;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ImageSpan;
import android.util.Log;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.TouchDelegate;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.Filter;
import android.widget.Filterable;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.TextView;

import com.squareup.picasso.Picasso;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;

public class AdapterRule extends RecyclerView.Adapter<AdapterRule.ViewHolder> implements Filterable {
    private static final String TAG = "NetGuard.Adapter";

    private Activity context;
    private RecyclerView rv;
    private int colorText;
    private int colorChanged;
    private int colorOn;
    private int colorOff;
    private int colorGrayed;
    private int iconSize;
    private boolean wifiActive = true;
    private boolean otherActive = true;
    private List<Rule> listAll = new ArrayList<>();
    private List<Rule> listFiltered = new ArrayList<>();

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public View view;

        public LinearLayout llApplication;
        public ImageView ivIcon;
        public ImageView ivExpander;
        public TextView tvName;

        public TextView tvHosts;

        public CheckBox cbWifi;
        public ImageView ivScreenWifi;

        public CheckBox cbOther;
        public ImageView ivScreenOther;
        public TextView tvRoaming;

        public LinearLayout llConfiguration;
        public TextView tvUid;
        public TextView tvPackage;
        public TextView tvVersion;
        public TextView tvDescription;
        public TextView tvInternet;
        public TextView tvDisabled;
        public TextView tvStatistics;

        public CheckBox cbApply;

        public Button btnRelated;
        public ImageButton ibSettings;
        public ImageButton ibLaunch;

        public ImageView ivWifiLegend;
        public CheckBox cbScreenWifi;

        public ImageView ivOtherLegend;
        public CheckBox cbScreenOther;
        public CheckBox cbRoaming;

        public ImageButton btnClear;

        public TextView tvNoLog;
        public TextView tvNoFilter;
        public ListView lvAccess;
        public ImageButton btnClearAccess;

        public CheckBox cbNotify;

        public ViewHolder(View itemView) {
            super(itemView);
            view = itemView;

            llApplication = (LinearLayout) itemView.findViewById(R.id.llApplication);
            ivIcon = (ImageView) itemView.findViewById(R.id.ivIcon);
            ivExpander = (ImageView) itemView.findViewById(R.id.ivExpander);
            tvName = (TextView) itemView.findViewById(R.id.tvName);

            tvHosts = (TextView) itemView.findViewById(R.id.tvHosts);

            cbWifi = (CheckBox) itemView.findViewById(R.id.cbWifi);
            ivScreenWifi = (ImageView) itemView.findViewById(R.id.ivScreenWifi);

            cbOther = (CheckBox) itemView.findViewById(R.id.cbOther);
            ivScreenOther = (ImageView) itemView.findViewById(R.id.ivScreenOther);
            tvRoaming = (TextView) itemView.findViewById(R.id.tvRoaming);

            llConfiguration = (LinearLayout) itemView.findViewById(R.id.llConfiguration);
            tvUid = (TextView) itemView.findViewById(R.id.tvUid);
            tvPackage = (TextView) itemView.findViewById(R.id.tvPackage);
            tvVersion = (TextView) itemView.findViewById(R.id.tvVersion);
            tvDescription = (TextView) itemView.findViewById(R.id.tvDescription);
            tvInternet = (TextView) itemView.findViewById(R.id.tvInternet);
            tvDisabled = (TextView) itemView.findViewById(R.id.tvDisabled);
            tvStatistics = (TextView) itemView.findViewById(R.id.tvStatistics);

            cbApply = (CheckBox) itemView.findViewById(R.id.cbApply);

            btnRelated = (Button) itemView.findViewById(R.id.btnRelated);
            ibSettings = (ImageButton) itemView.findViewById(R.id.ibSettings);
            ibLaunch = (ImageButton) itemView.findViewById(R.id.ibLaunch);

            ivWifiLegend = (ImageView) itemView.findViewById(R.id.ivWifiLegend);
            cbScreenWifi = (CheckBox) itemView.findViewById(R.id.cbScreenWifi);

            ivOtherLegend = (ImageView) itemView.findViewById(R.id.ivOtherLegend);
            cbScreenOther = (CheckBox) itemView.findViewById(R.id.cbScreenOther);
            cbRoaming = (CheckBox) itemView.findViewById(R.id.cbRoaming);

            btnClear = (ImageButton) itemView.findViewById(R.id.btnClear);

            tvNoLog = (TextView) itemView.findViewById(R.id.tvNoLog);
            tvNoFilter = (TextView) itemView.findViewById(R.id.tvNoFilter);
            lvAccess = (ListView) itemView.findViewById(R.id.lvAccess);
            btnClearAccess = (ImageButton) itemView.findViewById(R.id.btnClearAccess);

            cbNotify = (CheckBox) itemView.findViewById(R.id.cbNotify);

            final View wifiParent = (View) cbWifi.getParent();
            wifiParent.post(new Runnable() {
                public void run() {
                    Rect rect = new Rect();
                    cbWifi.getHitRect(rect);
                    rect.bottom += rect.top;
                    rect.right += rect.left;
                    rect.top = 0;
                    rect.left = 0;
                    wifiParent.setTouchDelegate(new TouchDelegate(rect, cbWifi));
                }
            });

            final View otherParent = (View) cbOther.getParent();
            otherParent.post(new Runnable() {
                public void run() {
                    Rect rect = new Rect();
                    cbOther.getHitRect(rect);
                    rect.bottom += rect.top;
                    rect.right += rect.left;
                    rect.top = 0;
                    rect.left = 0;
                    otherParent.setTouchDelegate(new TouchDelegate(rect, cbOther));
                }
            });
        }
    }

    public AdapterRule(Activity context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        this.context = context;

        if (prefs.getBoolean("dark_theme", false))
            colorChanged = Color.argb(128, Color.red(Color.DKGRAY), Color.green(Color.DKGRAY), Color.blue(Color.DKGRAY));
        else
            colorChanged = Color.argb(128, Color.red(Color.LTGRAY), Color.green(Color.LTGRAY), Color.blue(Color.LTGRAY));

        TypedArray ta = context.getTheme().obtainStyledAttributes(new int[]{android.R.attr.textColorSecondary});
        try {
            colorText = ta.getColor(0, 0);
        } finally {
            ta.recycle();
        }

        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        colorOn = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        colorOff = tv.data;

        colorGrayed = ContextCompat.getColor(context, R.color.colorGrayed);

        iconSize = Util.dips2pixels(48, context);
    }

    public void set(List<Rule> listRule) {
        listAll = listRule;
        listFiltered = new ArrayList<>();
        listFiltered.addAll(listRule);
        notifyDataSetChanged();
    }

    public void setWifiActive() {
        wifiActive = true;
        otherActive = false;
        notifyDataSetChanged();
    }

    public void setMobileActive() {
        wifiActive = false;
        otherActive = true;
        notifyDataSetChanged();
    }

    public void setDisconnected() {
        wifiActive = false;
        otherActive = false;
        notifyDataSetChanged();
    }

    @Override
    public void onAttachedToRecyclerView(RecyclerView recyclerView) {
        super.onAttachedToRecyclerView(recyclerView);
        rv = recyclerView;
    }

    @Override
    public void onDetachedFromRecyclerView(RecyclerView recyclerView) {
        super.onDetachedFromRecyclerView(recyclerView);
        rv = null;
    }

    @Override
    public void onBindViewHolder(final ViewHolder holder, final int position) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        // Get rule
        final Rule rule = listFiltered.get(position);

        // Handle expanding/collapsing
        holder.llApplication.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                rule.expanded = !rule.expanded;
                notifyItemChanged(position);
            }
        });

        // Show if non default rules
        holder.itemView.setBackgroundColor(rule.changed ? colorChanged : Color.TRANSPARENT);

        // Show expand/collapse indicator
        holder.ivExpander.setImageLevel(rule.expanded ? 1 : 0);

        // Show application icon
        if (rule.info.applicationInfo == null || rule.info.applicationInfo.icon == 0)
            Picasso.with(context).load(android.R.drawable.sym_def_app_icon).into(holder.ivIcon);
        else {
            Uri uri = Uri.parse("android.resource://" + rule.info.packageName + "/" + rule.info.applicationInfo.icon);
            Picasso.with(context).load(uri).resize(iconSize, iconSize).into(holder.ivIcon);
        }

        // Show application label
        holder.tvName.setText(rule.name);

        // Show application state
        int color = rule.system ? colorOff : colorText;
        if (!rule.internet || !rule.enabled)
            color = Color.argb(128, Color.red(color), Color.green(color), Color.blue(color));
        holder.tvName.setTextColor(color);

        // Show rule count
        new AsyncTask<Object, Object, Long>() {
            @Override
            protected void onPreExecute() {
                holder.tvHosts.setVisibility(View.GONE);
            }

            @Override
            protected Long doInBackground(Object... objects) {
                return DatabaseHelper.getInstance(context).getRuleCount(rule.info.applicationInfo.uid);
            }

            @Override
            protected void onPostExecute(Long rules) {
                if (rules > 0) {
                    holder.tvHosts.setVisibility(View.VISIBLE);
                    holder.tvHosts.setText(Long.toString(rules));
                }
            }
        }.execute();

        // Wi-Fi settings
        holder.cbWifi.setEnabled(rule.apply);
        holder.cbWifi.setAlpha(wifiActive ? 1 : 0.5f);
        holder.cbWifi.setOnCheckedChangeListener(null);
        holder.cbWifi.setChecked(rule.wifi_blocked);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(CompoundButtonCompat.getButtonDrawable(holder.cbWifi));
            DrawableCompat.setTint(wrap, rule.apply ? (rule.wifi_blocked ? colorOff : colorOn) : colorGrayed);
        }
        holder.cbWifi.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean isChecked) {
                rule.wifi_blocked = isChecked;
                updateRule(rule, true, listAll);
            }
        });

        holder.ivScreenWifi.setEnabled(rule.apply);
        holder.ivScreenWifi.setAlpha(wifiActive ? 1 : 0.5f);
        holder.ivScreenWifi.setVisibility(rule.screen_wifi && rule.wifi_blocked ? View.VISIBLE : View.INVISIBLE);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(holder.ivScreenWifi.getDrawable());
            DrawableCompat.setTint(wrap, rule.apply ? colorOn : colorGrayed);
        }

        // Mobile settings
        holder.cbOther.setEnabled(rule.apply);
        holder.cbOther.setAlpha(otherActive ? 1 : 0.5f);
        holder.cbOther.setOnCheckedChangeListener(null);
        holder.cbOther.setChecked(rule.other_blocked);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(CompoundButtonCompat.getButtonDrawable(holder.cbOther));
            DrawableCompat.setTint(wrap, rule.apply ? (rule.other_blocked ? colorOff : colorOn) : colorGrayed);
        }
        holder.cbOther.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean isChecked) {
                rule.other_blocked = isChecked;
                updateRule(rule, true, listAll);
            }
        });

        holder.ivScreenOther.setEnabled(rule.apply);
        holder.ivScreenOther.setAlpha(otherActive ? 1 : 0.5f);
        holder.ivScreenOther.setVisibility(rule.screen_other && rule.other_blocked ? View.VISIBLE : View.INVISIBLE);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(holder.ivScreenOther.getDrawable());
            DrawableCompat.setTint(wrap, rule.apply ? colorOn : colorGrayed);
        }

        holder.tvRoaming.setTextColor(rule.apply ? colorOff : colorGrayed);
        holder.tvRoaming.setAlpha(otherActive ? 1 : 0.5f);
        holder.tvRoaming.setVisibility(rule.roaming && (!rule.other_blocked || rule.screen_other) ? View.VISIBLE : View.INVISIBLE);

        // Expanded configuration section
        holder.llConfiguration.setVisibility(rule.expanded ? View.VISIBLE : View.GONE);

        // Show application details
        holder.tvUid.setText(rule.info.applicationInfo == null ? "?" : Integer.toString(rule.info.applicationInfo.uid));
        holder.tvPackage.setText(rule.info.packageName);
        holder.tvVersion.setText(rule.info.versionName + '/' + rule.info.versionCode);
        holder.tvDescription.setVisibility(rule.description == null ? View.GONE : View.VISIBLE);
        holder.tvDescription.setText(rule.description);

        // Show application state
        holder.tvInternet.setVisibility(rule.internet ? View.GONE : View.VISIBLE);
        holder.tvDisabled.setVisibility(rule.enabled ? View.GONE : View.VISIBLE);

        // Show traffic statistics
        holder.tvStatistics.setVisibility(Build.VERSION.SDK_INT >= Build.VERSION_CODES.N ? View.GONE : View.VISIBLE);
        holder.tvStatistics.setText(context.getString(R.string.msg_mbday, rule.upspeed, rule.downspeed));

        // Apply
        holder.cbApply.setEnabled(rule.pkg);
        holder.cbApply.setOnCheckedChangeListener(null);
        holder.cbApply.setChecked(rule.apply);
        holder.cbApply.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean isChecked) {
                rule.apply = isChecked;
                updateRule(rule, true, listAll);
            }
        });

        // Show related
        holder.btnRelated.setVisibility(rule.relateduids ? View.VISIBLE : View.GONE);
        holder.btnRelated.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent main = new Intent(context, ActivityMain.class);
                main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(rule.info.applicationInfo.uid));
                context.startActivity(main);
            }
        });

        // Launch application settings
        final Intent settings = new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
        settings.setData(Uri.parse("package:" + rule.info.packageName));
        holder.ibSettings.setVisibility(settings.resolveActivity(context.getPackageManager()) == null ? View.GONE : View.VISIBLE);
        holder.ibSettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(settings);
            }
        });

        // Launch application
        holder.ibLaunch.setVisibility(rule.intent == null ? View.GONE : View.VISIBLE);
        holder.ibLaunch.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(rule.intent);
            }
        });

        // Show Wi-Fi screen on condition
        holder.cbScreenWifi.setEnabled(rule.wifi_blocked && rule.apply);
        holder.cbScreenWifi.setOnCheckedChangeListener(null);
        holder.cbScreenWifi.setChecked(rule.screen_wifi);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(holder.ivWifiLegend.getDrawable());
            DrawableCompat.setTint(wrap, colorOn);
        }

        holder.cbScreenWifi.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                rule.screen_wifi = isChecked;
                updateRule(rule, true, listAll);
            }
        });


        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(holder.ivOtherLegend.getDrawable());
            DrawableCompat.setTint(wrap, colorOn);
        }

        // Show mobile screen on condition
        holder.cbScreenOther.setEnabled(rule.other_blocked && rule.apply);
        holder.cbScreenOther.setOnCheckedChangeListener(null);
        holder.cbScreenOther.setChecked(rule.screen_other);
        holder.cbScreenOther.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                rule.screen_other = isChecked;
                updateRule(rule, true, listAll);
            }
        });

        // Show roaming condition
        holder.cbRoaming.setEnabled((!rule.other_blocked || rule.screen_other) && rule.apply);
        holder.cbRoaming.setOnCheckedChangeListener(null);
        holder.cbRoaming.setChecked(rule.roaming);
        holder.cbRoaming.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            @TargetApi(Build.VERSION_CODES.M)
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                rule.roaming = isChecked;
                updateRule(rule, true, listAll);

                // Request permissions
                if (isChecked && !Util.hasPhoneStatePermission(context))
                    context.requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, ActivityMain.REQUEST_ROAMING);
            }
        });

        // Reset rule
        holder.btnClear.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Util.areYouSure(view.getContext(), R.string.msg_clear_rules, new Util.DoubtListener() {
                    @Override
                    public void onSure() {
                        holder.cbApply.setChecked(true);
                        holder.cbWifi.setChecked(rule.wifi_default);
                        holder.cbOther.setChecked(rule.other_default);
                        holder.cbScreenWifi.setChecked(rule.screen_wifi_default);
                        holder.cbScreenOther.setChecked(rule.screen_other_default);
                        holder.cbRoaming.setChecked(rule.roaming_default);
                    }
                });
            }
        });

        // Show logging is disabled
        boolean log_app = prefs.getBoolean("log_app", false);
        holder.tvNoLog.setVisibility(log_app ? View.GONE : View.VISIBLE);
        holder.tvNoLog.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(new Intent(context, ActivitySettings.class));
            }
        });

        // Show filtering is disabled
        boolean filter = prefs.getBoolean("filter", false);
        holder.tvNoFilter.setVisibility(filter ? View.GONE : View.VISIBLE);
        holder.tvNoFilter.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(new Intent(context, ActivitySettings.class));
            }
        });

        // Show access rules
        if (rule.expanded) {
            // Access the database when expanded only
            final AdapterAccess badapter = new AdapterAccess(context,
                    DatabaseHelper.getInstance(context).getAccess(rule.info.applicationInfo.uid));
            holder.lvAccess.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                @Override
                public void onItemClick(AdapterView<?> parent, View view, final int bposition, long bid) {
                    PackageManager pm = context.getPackageManager();
                    Cursor cursor = (Cursor) badapter.getItem(bposition);
                    final long id = cursor.getLong(cursor.getColumnIndex("ID"));
                    final int version = cursor.getInt(cursor.getColumnIndex("version"));
                    final int protocol = cursor.getInt(cursor.getColumnIndex("protocol"));
                    final String daddr = cursor.getString(cursor.getColumnIndex("daddr"));
                    final int dport = cursor.getInt(cursor.getColumnIndex("dport"));
                    long time = cursor.getLong(cursor.getColumnIndex("time"));
                    int block = cursor.getInt(cursor.getColumnIndex("block"));

                    PopupMenu popup = new PopupMenu(context, context.findViewById(R.id.vwPopupAnchor));
                    popup.inflate(R.menu.access);

                    popup.getMenu().findItem(R.id.menu_host).setTitle(
                            Util.getProtocolName(protocol, version, false) + " " +
                                    daddr + (dport > 0 ? "/" + dport : ""));

                    markPro(popup.getMenu().findItem(R.id.menu_allow), ActivityPro.SKU_FILTER);
                    markPro(popup.getMenu().findItem(R.id.menu_block), ActivityPro.SKU_FILTER);

                    // Whois
                    final Intent lookupIP = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.tcpiputils.com/whois-lookup/" + daddr));
                    if (pm.resolveActivity(lookupIP, 0) == null)
                        popup.getMenu().removeItem(R.id.menu_whois);
                    else
                        popup.getMenu().findItem(R.id.menu_whois).setTitle(context.getString(R.string.title_log_whois, daddr));

                    // Lookup port
                    final Intent lookupPort = new Intent(Intent.ACTION_VIEW, Uri.parse("http://www.speedguide.net/port.php?port=" + dport));
                    if (dport <= 0 || pm.resolveActivity(lookupPort, 0) == null)
                        popup.getMenu().removeItem(R.id.menu_port);
                    else
                        popup.getMenu().findItem(R.id.menu_port).setTitle(context.getString(R.string.title_log_port, dport));

                    popup.getMenu().findItem(R.id.menu_time).setTitle(
                            SimpleDateFormat.getDateTimeInstance().format(time));

                    popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
                        @Override
                        public boolean onMenuItemClick(MenuItem menuItem) {
                            switch (menuItem.getItemId()) {
                                case R.id.menu_whois:
                                    context.startActivity(lookupIP);
                                    return true;

                                case R.id.menu_port:
                                    context.startActivity(lookupPort);
                                    return true;

                                case R.id.menu_allow:
                                    if (IAB.isPurchased(ActivityPro.SKU_FILTER, context)) {
                                        DatabaseHelper.getInstance(context).setAccess(id, 0);
                                        ServiceSinkhole.reload("allow host", context);
                                    } else
                                        context.startActivity(new Intent(context, ActivityPro.class));
                                    return true;

                                case R.id.menu_block:
                                    if (IAB.isPurchased(ActivityPro.SKU_FILTER, context)) {
                                        DatabaseHelper.getInstance(context).setAccess(id, 1);
                                        ServiceSinkhole.reload("block host", context);
                                    } else
                                        context.startActivity(new Intent(context, ActivityPro.class));
                                    return true;

                                case R.id.menu_reset:
                                    DatabaseHelper.getInstance(context).setAccess(id, -1);
                                    ServiceSinkhole.reload("reset host", context);
                                    return true;
                            }
                            return false;
                        }
                    });

                    if (block == 0)
                        popup.getMenu().removeItem(R.id.menu_allow);
                    else if (block == 1)
                        popup.getMenu().removeItem(R.id.menu_block);

                    popup.show();
                }
            });

            holder.lvAccess.setAdapter(badapter);
        } else {
            holder.lvAccess.setAdapter(null);
            holder.lvAccess.setOnItemClickListener(null);
        }

        // Clear access log
        holder.btnClearAccess.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Util.areYouSure(view.getContext(), R.string.msg_reset_access, new Util.DoubtListener() {
                    @Override
                    public void onSure() {
                        DatabaseHelper.getInstance(context).clearAccess(rule.info.applicationInfo.uid, true);
                        if (rv != null)
                            rv.scrollToPosition(position);
                    }
                });
            }
        });

        // Notify on access
        holder.cbNotify.setEnabled(prefs.getBoolean("notify_access", false) && rule.apply);
        holder.cbNotify.setOnCheckedChangeListener(null);
        holder.cbNotify.setChecked(rule.notify);
        holder.cbNotify.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean isChecked) {
                rule.notify = isChecked;
                updateRule(rule, true, listAll);
            }
        });
    }

    private void markPro(MenuItem menu, String sku) {
        if (sku == null || !IAB.isPurchased(sku, context)) {
            SpannableStringBuilder ssb = new SpannableStringBuilder("  " + menu.getTitle());
            ssb.setSpan(new ImageSpan(context, R.drawable.ic_shopping_cart_white_24dp), 0, 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            menu.setTitle(ssb);
        }
    }

    private void updateRule(Rule rule, boolean root, List<Rule> listAll) {
        SharedPreferences wifi = context.getSharedPreferences("wifi", Context.MODE_PRIVATE);
        SharedPreferences other = context.getSharedPreferences("other", Context.MODE_PRIVATE);
        SharedPreferences apply = context.getSharedPreferences("apply", Context.MODE_PRIVATE);
        SharedPreferences screen_wifi = context.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE);
        SharedPreferences screen_other = context.getSharedPreferences("screen_other", Context.MODE_PRIVATE);
        SharedPreferences roaming = context.getSharedPreferences("roaming", Context.MODE_PRIVATE);
        SharedPreferences notify = context.getSharedPreferences("notify", Context.MODE_PRIVATE);

        if (rule.wifi_blocked == rule.wifi_default)
            wifi.edit().remove(rule.info.packageName).apply();
        else
            wifi.edit().putBoolean(rule.info.packageName, rule.wifi_blocked).apply();

        if (rule.other_blocked == rule.other_default)
            other.edit().remove(rule.info.packageName).apply();
        else
            other.edit().putBoolean(rule.info.packageName, rule.other_blocked).apply();

        if (rule.apply)
            apply.edit().remove(rule.info.packageName).apply();
        else
            apply.edit().putBoolean(rule.info.packageName, rule.apply).apply();

        if (rule.screen_wifi == rule.screen_wifi_default)
            screen_wifi.edit().remove(rule.info.packageName).apply();
        else
            screen_wifi.edit().putBoolean(rule.info.packageName, rule.screen_wifi).apply();

        if (rule.screen_other == rule.screen_other_default)
            screen_other.edit().remove(rule.info.packageName).apply();
        else
            screen_other.edit().putBoolean(rule.info.packageName, rule.screen_other).apply();

        if (rule.roaming == rule.roaming_default)
            roaming.edit().remove(rule.info.packageName).apply();
        else
            roaming.edit().putBoolean(rule.info.packageName, rule.roaming).apply();

        if (rule.notify)
            notify.edit().remove(rule.info.packageName).apply();
        else
            notify.edit().putBoolean(rule.info.packageName, rule.notify).apply();

        rule.updateChanged(context);
        Log.i(TAG, "Updated " + rule);

        List<Rule> listModified = new ArrayList<>();
        for (String pkg : rule.related) {
            for (Rule related : listAll)
                if (related.info.packageName.equals(pkg)) {
                    related.wifi_blocked = rule.wifi_blocked;
                    related.other_blocked = rule.other_blocked;
                    related.apply = rule.apply;
                    related.screen_wifi = rule.screen_wifi;
                    related.screen_other = rule.screen_other;
                    related.roaming = rule.roaming;
                    related.notify = rule.notify;
                    listModified.add(related);
                }
        }

        List<Rule> listSearch = (root ? new ArrayList<>(listAll) : listAll);
        listSearch.remove(rule);
        for (Rule modified : listModified)
            listSearch.remove(modified);
        for (Rule modified : listModified)
            updateRule(modified, false, listSearch);

        if (root) {
            notifyDataSetChanged();
            NotificationManagerCompat.from(context).cancel(rule.info.applicationInfo.uid);
            ServiceSinkhole.reload("rule changed", context);
        }
    }

    @Override
    public Filter getFilter() {
        return new Filter() {
            @Override
            protected FilterResults performFiltering(CharSequence query) {
                List<Rule> listResult = new ArrayList<>();
                if (query == null)
                    listResult.addAll(listAll);
                else {
                    query = query.toString().toLowerCase().trim();
                    int uid;
                    try {
                        uid = Integer.parseInt(query.toString());
                    } catch (NumberFormatException ignore) {
                        uid = -1;
                    }
                    for (Rule rule : listAll)
                        if (rule.info.applicationInfo.uid == uid ||
                                rule.info.packageName.toLowerCase().contains(query) ||
                                (rule.name != null && rule.name.toLowerCase().contains(query)))
                            listResult.add(rule);
                }

                FilterResults result = new FilterResults();
                result.values = listResult;
                result.count = listResult.size();
                return result;
            }

            @Override
            protected void publishResults(CharSequence query, FilterResults result) {
                listFiltered.clear();
                if (result == null)
                    listFiltered.addAll(listAll);
                else {
                    listFiltered.addAll((List<Rule>) result.values);
                    if (listFiltered.size() == 1)
                        listFiltered.get(0).expanded = true;
                }
                notifyDataSetChanged();
            }
        };
    }

    @Override
    public AdapterRule.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        return new ViewHolder(LayoutInflater.from(context).inflate(R.layout.rule, parent, false));
    }

    @Override
    public int getItemCount() {
        return listFiltered.size();
    }
}
