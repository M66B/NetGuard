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
import android.support.v4.graphics.drawable.DrawableCompat;
import android.support.v4.widget.CompoundButtonCompat;
import android.support.v7.widget.RecyclerView;
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

public class RuleAdapter extends RecyclerView.Adapter<RuleAdapter.ViewHolder> implements Filterable {
    private static final String TAG = "NetGuard.Adapter";

    private Activity context;
    private DatabaseHelper dh;
    private RecyclerView rv;
    private boolean filter;
    private boolean debuggable;
    private int colorText;
    private int colorAccent;
    private int colorChanged;
    private int colorOn;
    private int colorOff;
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
        public TextView tvDisabled;
        public TextView tvInternet;

        public ImageView ivWifiLegend;
        public CheckBox cbScreenWifi;

        public ImageView ivOtherLegend;
        public CheckBox cbScreenOther;
        public CheckBox cbRoaming;

        public ImageButton btnClear;
        public ImageButton btnSettings;
        public Button btnLaunch;

        public ListView lvAccess;
        public TextView tvNolog;
        public CheckBox cbNotify;
        public ImageButton btnClearAccess;
        public TextView tvStatistics;

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
            tvDisabled = (TextView) itemView.findViewById(R.id.tvDisabled);
            tvInternet = (TextView) itemView.findViewById(R.id.tvInternet);

            ivWifiLegend = (ImageView) itemView.findViewById(R.id.ivWifiLegend);
            cbScreenWifi = (CheckBox) itemView.findViewById(R.id.cbScreenWifi);

            ivOtherLegend = (ImageView) itemView.findViewById(R.id.ivOtherLegend);
            cbScreenOther = (CheckBox) itemView.findViewById(R.id.cbScreenOther);
            cbRoaming = (CheckBox) itemView.findViewById(R.id.cbRoaming);

            btnClear = (ImageButton) itemView.findViewById(R.id.btnClear);
            btnSettings = (ImageButton) itemView.findViewById(R.id.btnSettings);
            btnLaunch = (Button) itemView.findViewById(R.id.btnLaunch);

            lvAccess = (ListView) itemView.findViewById(R.id.lvAccess);
            tvNolog = (TextView) itemView.findViewById(R.id.tvNolog);
            cbNotify = (CheckBox) itemView.findViewById(R.id.cbNotify);
            btnClearAccess = (ImageButton) itemView.findViewById(R.id.btnClearAccess);
            tvStatistics = (TextView) itemView.findViewById(R.id.tvStatistics);

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

    public RuleAdapter(DatabaseHelper dh, Activity context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        this.context = context;
        this.dh = dh;
        this.filter = prefs.getBoolean("filter", false);
        this.debuggable = Util.isDebuggable(context);

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
        context.getTheme().resolveAttribute(R.attr.colorAccent, tv, true);
        colorAccent = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        colorOn = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        colorOff = tv.data;
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
        // Get rule
        final Rule rule = listFiltered.get(position);

        // Rule change listener
        CompoundButton.OnCheckedChangeListener cbListener = new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                // Update rule
                String network = ((buttonView == holder.cbWifi) ? "wifi" : "other");
                updateRule(rule, network, isChecked);
                rule.updateChanged(context);

                // Update relations
                if (rule.related == null)
                    notifyItemChanged(position);
                else {
                    for (String pkg : rule.related)
                        for (Rule related : listAll)
                            if (related.info.packageName.equals(pkg)) {
                                updateRule(related, network, isChecked);
                                updateScreenWifi(related, rule.screen_wifi);
                                updateScreenOther(related, rule.screen_other);
                                updateRoaming(related, rule.roaming);
                                related.updateChanged(context);
                            }
                    notifyDataSetChanged();
                }

                // Apply updated rule
                SinkholeService.reload(network, "rule changed", context);
            }
        };

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
            Picasso.with(context).load(uri).into(holder.ivIcon);
        }

        // Show application label
        holder.tvName.setText(rule.name);

        // Show application state
        int color = rule.system ? colorAccent : colorText;
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
                return dh.getRuleCount(rule.info.applicationInfo.uid);
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
        holder.cbWifi.setAlpha(wifiActive ? 1 : 0.5f);
        holder.cbWifi.setOnCheckedChangeListener(null);
        holder.cbWifi.setChecked(rule.wifi_blocked);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(CompoundButtonCompat.getButtonDrawable(holder.cbWifi));
            DrawableCompat.setTint(wrap, rule.wifi_blocked ? colorOff : colorOn);
        }
        holder.cbWifi.setOnCheckedChangeListener(cbListener);

        holder.ivScreenWifi.setAlpha(wifiActive ? 1 : 0.5f);
        holder.ivScreenWifi.setVisibility(rule.screen_wifi && rule.wifi_blocked ? View.VISIBLE : View.INVISIBLE);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(holder.ivScreenWifi.getDrawable());
            DrawableCompat.setTint(wrap, colorOn);
        }

        // Mobile settings
        holder.cbOther.setAlpha(otherActive ? 1 : 0.5f);
        holder.cbOther.setOnCheckedChangeListener(null);
        holder.cbOther.setChecked(rule.other_blocked);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(CompoundButtonCompat.getButtonDrawable(holder.cbOther));
            DrawableCompat.setTint(wrap, rule.other_blocked ? colorOff : colorOn);
        }
        holder.cbOther.setOnCheckedChangeListener(cbListener);

        holder.ivScreenOther.setAlpha(otherActive ? 1 : 0.5f);
        holder.ivScreenOther.setVisibility(rule.screen_other && rule.other_blocked ? View.VISIBLE : View.INVISIBLE);
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(holder.ivScreenOther.getDrawable());
            DrawableCompat.setTint(wrap, colorOn);
        }

        holder.tvRoaming.setAlpha(otherActive ? 1 : 0.5f);
        holder.tvRoaming.setVisibility(rule.roaming && (!rule.other_blocked || rule.screen_other) ? View.VISIBLE : View.INVISIBLE);

        // Expanded configuration section
        holder.llConfiguration.setVisibility(rule.expanded ? View.VISIBLE : View.GONE);

        // Show application details
        holder.tvUid.setText(rule.info.applicationInfo == null ? "?" : Integer.toString(rule.info.applicationInfo.uid));
        holder.tvPackage.setText(rule.info.packageName);
        holder.tvVersion.setText(rule.info.versionName + '/' + rule.info.versionCode);

        // Show application state
        holder.tvDisabled.setVisibility(rule.enabled ? View.GONE : View.VISIBLE);
        holder.tvInternet.setVisibility(rule.internet ? View.GONE : View.VISIBLE);

        // Launch application settings
        final Intent settings = new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
        settings.setData(Uri.parse("package:" + rule.info.packageName));
        holder.btnSettings.setVisibility(
                !debuggable || settings.resolveActivity(context.getPackageManager()) == null ? View.GONE : View.VISIBLE);
        holder.btnSettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(settings);
            }
        });

        // Launch application
        holder.btnLaunch.setVisibility(!debuggable || rule.intent == null ? View.GONE : View.VISIBLE);
        holder.btnLaunch.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(rule.intent);
            }
        });

        // Show Wi-Fi screen on condition
        holder.cbScreenWifi.setOnCheckedChangeListener(null);
        holder.cbScreenWifi.setChecked(rule.screen_wifi);
        holder.cbScreenWifi.setEnabled(rule.wifi_blocked);

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(holder.ivWifiLegend.getDrawable());
            DrawableCompat.setTint(wrap, colorOn);
        }

        holder.cbScreenWifi.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                // Update rule
                updateScreenWifi(rule, isChecked);
                rule.updateChanged(context);

                // Update relations
                if (rule.related == null)
                    notifyItemChanged(position);
                else {
                    for (String pkg : rule.related)
                        for (Rule related : listAll)
                            if (related.info.packageName.equals(pkg)) {
                                updateScreenWifi(related, rule.screen_wifi);
                                related.updateChanged(context);
                            }
                    notifyDataSetChanged();
                }

                // Apply updated rule
                SinkholeService.reload(null, "rule changed", context);
            }
        });


        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(holder.ivOtherLegend.getDrawable());
            DrawableCompat.setTint(wrap, colorOn);
        }

        // Show mobile screen on condition
        holder.cbScreenOther.setOnCheckedChangeListener(null);
        holder.cbScreenOther.setChecked(rule.screen_other);
        holder.cbScreenOther.setEnabled(rule.other_blocked);

        holder.cbScreenOther.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                // Update rule
                updateScreenOther(rule, isChecked);
                rule.updateChanged(context);

                // Update relations
                if (rule.related == null)
                    notifyItemChanged(position);
                else {
                    for (String pkg : rule.related)
                        for (Rule related : listAll)
                            if (related.info.packageName.equals(pkg)) {
                                updateScreenOther(related, rule.screen_other);
                                related.updateChanged(context);
                            }
                    notifyDataSetChanged();
                }

                // Apply updated rule
                SinkholeService.reload(null, "rule changed", context);
            }
        });

        // Show roaming condition
        holder.cbRoaming.setOnCheckedChangeListener(null);
        holder.cbRoaming.setChecked(rule.roaming);
        holder.cbRoaming.setEnabled(!rule.other_blocked || rule.screen_other);

        holder.cbRoaming.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            @TargetApi(Build.VERSION_CODES.M)
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                // Update rule
                updateRoaming(rule, isChecked);
                rule.updateChanged(context);

                // Update relations
                if (rule.related == null)
                    notifyItemChanged(position);
                else {
                    for (String pkg : rule.related)
                        for (Rule related : listAll)
                            if (related.info.packageName.equals(pkg)) {
                                updateRoaming(related, rule.roaming);
                                related.updateChanged(context);
                            }
                    notifyDataSetChanged();
                }

                // Apply updated rule
                SinkholeService.reload(null, "rule changed", context);

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
                        holder.cbWifi.setChecked(rule.wifi_default);
                        holder.cbOther.setChecked(rule.other_default);
                        holder.cbScreenWifi.setChecked(rule.screen_wifi_default);
                        holder.cbScreenOther.setChecked(rule.screen_other_default);
                        holder.cbRoaming.setChecked(rule.roaming_default);
                    }
                });
            }
        });

        // Show access rules
        if (rule.expanded) {
            // Access the database when expanded only
            final AccessAdapter badapter = new AccessAdapter(context, dh.getAccess(rule.info.applicationInfo.uid));
            if (filter)
                holder.lvAccess.setOnItemClickListener(new AdapterView.OnItemClickListener() {
                    @Override
                    public void onItemClick(AdapterView<?> parent, View view, final int bposition, long bid) {
                        if (IAB.isPurchased(ActivityPro.SKU_FILTER, context)) {
                            Cursor cursor = (Cursor) badapter.getItem(bposition);
                            final long id = cursor.getLong(cursor.getColumnIndex("ID"));
                            int version = cursor.getInt(cursor.getColumnIndex("version"));
                            int protocol = cursor.getInt(cursor.getColumnIndex("protocol"));
                            String daddr = cursor.getString(cursor.getColumnIndex("daddr"));
                            int dport = cursor.getInt(cursor.getColumnIndex("dport"));
                            long time = cursor.getLong(cursor.getColumnIndex("time"));
                            int block = cursor.getInt(cursor.getColumnIndex("block"));

                            PopupMenu popup = new PopupMenu(context, context.findViewById(R.id.vwPopupAnchor));
                            popup.inflate(R.menu.access);
                            popup.getMenu().findItem(R.id.menu_host).setTitle(
                                    Util.getProtocolName(protocol, version, false) + " " +
                                            daddr + (dport > 0 ? ":" + dport : ""));
                            popup.getMenu().findItem(R.id.menu_time).setTitle(
                                    SimpleDateFormat.getDateTimeInstance().format(time));

                            popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
                                @Override
                                public boolean onMenuItemClick(MenuItem menuItem) {
                                    switch (menuItem.getItemId()) {
                                        case R.id.menu_allow:
                                            dh.setAccess(id, 0);
                                            SinkholeService.reload(null, "allow host", context);
                                            return true;
                                        case R.id.menu_block:
                                            dh.setAccess(id, 1);
                                            SinkholeService.reload(null, "block host", context);
                                            return true;
                                        case R.id.menu_reset:
                                            dh.setAccess(id, -1);
                                            SinkholeService.reload(null, "reset host", context);
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
                        } else
                            context.startActivity(new Intent(context, ActivityPro.class));
                    }
                });
            else
                holder.lvAccess.setOnItemClickListener(null);

            holder.lvAccess.setAdapter(badapter);
        } else {
            holder.lvAccess.setAdapter(null);
            holder.lvAccess.setOnItemClickListener(null);
        }

        // Show logging is disabled
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        boolean log_app = prefs.getBoolean("log_app", false);
        holder.tvNolog.setVisibility(log_app ? View.GONE : View.VISIBLE);
        holder.tvNolog.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(new Intent(context, ActivitySettings.class));
            }
        });

        // Show disable access notifications setting
        boolean notify = prefs.getBoolean("notify_access", false);
        final String key = "notify_" + rule.info.applicationInfo.uid;
        holder.cbNotify.setOnCheckedChangeListener(null);
        holder.cbNotify.setEnabled(notify);
        holder.cbNotify.setChecked(prefs.getBoolean(key, true));
        holder.cbNotify.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean isChecked) {
                prefs.edit().putBoolean(key, isChecked).apply();
            }
        });

        // Clear access log
        holder.btnClearAccess.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Util.areYouSure(view.getContext(), R.string.msg_reset_access, new Util.DoubtListener() {
                    @Override
                    public void onSure() {
                        dh.clearAccess(rule.info.applicationInfo.uid);
                        if (rv != null)
                            rv.scrollToPosition(position);
                    }
                });
            }
        });

        // Show traffic statistics
        holder.tvStatistics.setText(context.getString(R.string.msg_mbday, rule.upspeed, rule.downspeed));
    }

    private void updateRule(Rule rule, String network, boolean blocked) {
        SharedPreferences prefs = context.getSharedPreferences(network, Context.MODE_PRIVATE);

        if ("wifi".equals(network)) {
            rule.wifi_blocked = blocked;
            if (rule.wifi_blocked == rule.wifi_default) {
                Log.i(TAG, "Removing " + rule.info.packageName + " " + network);
                prefs.edit().remove(rule.info.packageName).apply();
            } else {
                Log.i(TAG, "Setting " + rule.info.packageName + " " + network + "=" + blocked);
                prefs.edit().putBoolean(rule.info.packageName, blocked).apply();
            }
        }

        if ("other".equals(network)) {
            rule.other_blocked = blocked;
            if (rule.other_blocked == rule.other_default) {
                Log.i(TAG, "Removing " + rule.info.packageName + " " + network);
                prefs.edit().remove(rule.info.packageName).apply();
            } else {
                Log.i(TAG, "Setting " + rule.info.packageName + " " + network + "=" + blocked);
                prefs.edit().putBoolean(rule.info.packageName, blocked).apply();
            }
        }

        NotificationManagerCompat.from(context).cancel(rule.info.applicationInfo.uid);
    }

    private void updateScreenWifi(Rule rule, boolean enabled) {
        rule.screen_wifi = enabled;
        SharedPreferences screen_wifi = context.getSharedPreferences("screen_wifi", Context.MODE_PRIVATE);
        if (rule.screen_wifi == rule.screen_wifi_default)
            screen_wifi.edit().remove(rule.info.packageName).apply();
        else
            screen_wifi.edit().putBoolean(rule.info.packageName, rule.screen_wifi).apply();
    }

    private void updateScreenOther(Rule rule, boolean enabled) {
        rule.screen_other = enabled;
        SharedPreferences screen_other = context.getSharedPreferences("screen_other", Context.MODE_PRIVATE);
        if (rule.screen_other == rule.screen_other_default)
            screen_other.edit().remove(rule.info.packageName).apply();
        else
            screen_other.edit().putBoolean(rule.info.packageName, rule.screen_other).apply();
    }

    private void updateRoaming(Rule rule, boolean enabled) {
        rule.roaming = enabled;
        SharedPreferences roaming = context.getSharedPreferences("roaming", Context.MODE_PRIVATE);
        if (rule.roaming == rule.roaming_default)
            roaming.edit().remove(rule.info.packageName).apply();
        else
            roaming.edit().putBoolean(rule.info.packageName, rule.roaming).apply();
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
                    query = query.toString().toLowerCase();
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
    public RuleAdapter.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        return new ViewHolder(LayoutInflater.from(context).inflate(R.layout.rule, parent, false));
    }

    @Override
    public int getItemCount() {
        return listFiltered.size();
    }
}
