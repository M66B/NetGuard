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

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.graphics.Rect;
import android.net.Uri;
import android.support.v4.content.ContextCompat;
import android.support.v7.widget.RecyclerView;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.TouchDelegate;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.Filter;
import android.widget.Filterable;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.squareup.picasso.Picasso;

import java.util.ArrayList;
import java.util.List;

public class RuleAdapter extends RecyclerView.Adapter<RuleAdapter.ViewHolder> implements Filterable {
    private static final String TAG = "NetGuard.Adapter";

    private Context context;
    private boolean debuggable;
    private int colorText;
    private int colorAccent;
    private List<Rule> listAll = new ArrayList<>();
    private List<Rule> listSelected = new ArrayList<>();

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public View view;

        public LinearLayout llApplication;
        public ImageView ivIcon;
        public ImageView ivExpander;
        public TextView tvName;
        public CheckBox cbWifi;
        public CheckBox cbOther;

        public LinearLayout llAttributes;
        public ImageView ivUsing;
        public TextView tvRoaming;

        public LinearLayout llConfiguration;
        public TextView tvPackage;
        public TextView tvDisabled;
        public TextView tvInternet;
        public CheckBox cbUsing;
        public CheckBox cbRoaming;
        public ImageButton btnSettings;
        public Button btnLaunch;

        public ViewHolder(View itemView) {
            super(itemView);
            view = itemView;

            llApplication = (LinearLayout) itemView.findViewById(R.id.llApplication);
            ivIcon = (ImageView) itemView.findViewById(R.id.ivIcon);
            ivExpander = (ImageView) itemView.findViewById(R.id.ivExpander);
            tvName = (TextView) itemView.findViewById(R.id.tvName);

            cbWifi = (CheckBox) itemView.findViewById(R.id.cbWifi);
            cbOther = (CheckBox) itemView.findViewById(R.id.cbOther);

            llAttributes = (LinearLayout) itemView.findViewById(R.id.llAttributes);
            ivUsing = (ImageView) itemView.findViewById(R.id.ivUsing);
            tvRoaming = (TextView) itemView.findViewById(R.id.tvRoaming);

            llConfiguration = (LinearLayout) itemView.findViewById(R.id.llConfiguration);
            tvPackage = (TextView) itemView.findViewById(R.id.tvPackage);
            tvDisabled = (TextView) itemView.findViewById(R.id.tvDisabled);
            tvInternet = (TextView) itemView.findViewById(R.id.tvInternet);
            cbUsing = (CheckBox) itemView.findViewById(R.id.cbUsing);
            cbRoaming = (CheckBox) itemView.findViewById(R.id.cbRoaming);
            btnSettings = (ImageButton) itemView.findViewById(R.id.btnSettings);
            btnLaunch = (Button) itemView.findViewById(R.id.btnLaunch);

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

    public RuleAdapter(Context context) {
        this.context = context;
        this.debuggable = Util.isDebuggable(context);
        colorAccent = ContextCompat.getColor(context, R.color.colorAccent);
        TypedArray ta = context.getTheme().obtainStyledAttributes(new int[]{android.R.attr.textColorSecondary});
        try {
            colorText = ta.getColor(0, 0);
        } finally {
            ta.recycle();
        }
    }

    public void set(List<Rule> listRule) {
        listAll = listRule;
        listSelected = new ArrayList<>();
        listSelected.addAll(listRule);
        notifyDataSetChanged();
    }

    @Override
    public void onBindViewHolder(final ViewHolder holder, final int position) {
        // Get rule
        final Rule rule = listSelected.get(position);

        // Rule change listener
        CompoundButton.OnCheckedChangeListener cbListener = new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                // Update rule
                String network = ((buttonView == holder.cbWifi) ? "wifi" : "other");
                updateRule(rule, network, isChecked);

                // Update relations
                if (rule.related == null)
                    notifyItemChanged(position);
                else {
                    for (String pkg : rule.related)
                        for (Rule related : listAll)
                            if (related.info.packageName.equals(pkg)) {
                                updateRule(related, network, isChecked);
                                updateUnused(related, rule.unused);
                                updateRoaming(related, rule.roaming);
                            }
                    notifyDataSetChanged();
                }

                // Apply updated rule
                SinkholeService.reload(network, context);
            }
        };

        View.OnClickListener llListener = new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                rule.attributes = !rule.attributes;
                notifyItemChanged(position);
            }
        };

        holder.llApplication.setOnClickListener(llListener);

        if (rule.info.applicationInfo == null || rule.info.applicationInfo.icon == 0)
            Picasso.with(context).load(android.R.drawable.sym_def_app_icon).into(holder.ivIcon);
        else {
            Uri uri = Uri.parse("android.resource://" + rule.info.packageName + "/" + rule.info.applicationInfo.icon);
            Picasso.with(context).load(uri).into(holder.ivIcon);
        }

        holder.ivExpander.setImageResource(rule.attributes ? android.R.drawable.arrow_up_float : android.R.drawable.arrow_down_float);
        holder.tvName.setText(rule.name);

        int color = rule.system ? colorAccent : colorText;
        if (!rule.internet || rule.disabled)
            color = Color.argb(100, Color.red(color), Color.green(color), Color.blue(color));
        holder.tvName.setTextColor(color);

        holder.cbWifi.setOnCheckedChangeListener(null);
        holder.cbWifi.setChecked(rule.wifi_blocked);
        holder.cbWifi.setOnCheckedChangeListener(cbListener);

        holder.cbOther.setOnCheckedChangeListener(null);
        holder.cbOther.setChecked(rule.other_blocked);
        holder.cbOther.setOnCheckedChangeListener(cbListener);

        holder.llAttributes.setOnClickListener(llListener);
        holder.ivUsing.setVisibility(rule.unused && (rule.wifi_blocked || rule.other_blocked) ? View.VISIBLE : View.INVISIBLE);
        holder.tvRoaming.setVisibility(rule.roaming && (!rule.other_blocked || rule.unused) ? View.VISIBLE : View.INVISIBLE);

        holder.llConfiguration.setVisibility(rule.attributes ? View.VISIBLE : View.GONE);
        if (!debuggable || rule.info.applicationInfo == null)
            holder.tvPackage.setText(rule.info.packageName);
        else
            holder.tvPackage.setText(rule.info.applicationInfo.uid + " " + rule.info.packageName);

        holder.tvDisabled.setVisibility(rule.disabled ? View.VISIBLE : View.GONE);
        holder.tvInternet.setVisibility(rule.internet ? View.GONE : View.VISIBLE);

        holder.cbUsing.setOnCheckedChangeListener(null);
        holder.cbUsing.setChecked(rule.unused);
        holder.cbUsing.setEnabled(rule.wifi_blocked || rule.other_blocked);

        holder.cbUsing.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                // Update rule
                updateUnused(rule, isChecked);

                // Update relations
                if (rule.related == null)
                    notifyItemChanged(position);
                else {
                    for (String pkg : rule.related)
                        for (Rule related : listAll)
                            if (related.info.packageName.equals(pkg))
                                updateUnused(related, rule.unused);
                    notifyDataSetChanged();
                }

                // Apply updated rule
                SinkholeService.reload(null, context);
            }
        });

        holder.cbRoaming.setOnCheckedChangeListener(null);
        holder.cbRoaming.setChecked(rule.roaming);
        holder.cbRoaming.setEnabled(!rule.other_blocked || rule.unused);

        holder.cbRoaming.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                // Update rule
                updateRoaming(rule, isChecked);

                // Update relations
                if (rule.related == null)
                    notifyItemChanged(position);
                else {
                    for (String pkg : rule.related)
                        for (Rule related : listAll)
                            if (related.info.packageName.equals(pkg))
                                updateRoaming(related, rule.roaming);
                    notifyDataSetChanged();
                }

                // Apply updated rule
                SinkholeService.reload(null, context);
            }
        });

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
    }

    private void updateUnused(Rule rule, boolean enabled) {
        rule.unused = enabled;
        SharedPreferences unused = context.getSharedPreferences("unused", Context.MODE_PRIVATE);
        if (rule.unused == rule.unused_default)
            unused.edit().remove(rule.info.packageName).apply();
        else
            unused.edit().putBoolean(rule.info.packageName, rule.unused).apply();
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
                    for (Rule rule : listAll)
                        if (rule.info.packageName.toLowerCase().contains(query) ||
                                (rule.name != null && rule.name.toLowerCase().contains(query)) ||
                                (debuggable && rule.info.applicationInfo != null &&
                                        Integer.toString(rule.info.applicationInfo.uid).contains(query)))
                            listResult.add(rule);
                }

                FilterResults result = new FilterResults();
                result.values = listResult;
                result.count = listResult.size();
                return result;
            }

            @Override
            protected void publishResults(CharSequence query, FilterResults result) {
                listSelected.clear();
                if (result == null)
                    listSelected.addAll(listAll);
                else
                    for (Rule rule : (List<Rule>) result.values)
                        listSelected.add(rule);
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
        return listSelected.size();
    }
}
