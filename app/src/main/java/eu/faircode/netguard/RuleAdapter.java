package eu.faircode.netguard;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.preference.PreferenceManager;
import android.support.v4.content.ContextCompat;
import android.support.v7.widget.RecyclerView;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.Filter;
import android.widget.Filterable;
import android.widget.ImageView;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

public class RuleAdapter extends RecyclerView.Adapter<RuleAdapter.ViewHolder> implements Filterable {
    private static final String TAG = "NetGuard.RuleAdapter";

    private Context context;
    private int colorText;
    private int colorAccent;
    private List<Rule> listAll;
    private List<Rule> listSelected;

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public View view;
        public ImageView ivIcon;
        public TextView tvName;
        public TextView tvPackage;
        public CheckBox cbWifi;
        public CheckBox cbOther;

        public ViewHolder(View itemView) {
            super(itemView);
            view = itemView;
            ivIcon = (ImageView) itemView.findViewById(R.id.ivIcon);
            tvName = (TextView) itemView.findViewById(R.id.tvName);
            tvPackage = (TextView) itemView.findViewById(R.id.tvPackage);
            cbWifi = (CheckBox) itemView.findViewById(R.id.cbWifi);
            cbOther = (CheckBox) itemView.findViewById(R.id.cbOther);
        }
    }

    public RuleAdapter(List<Rule> listRule, Context context) {
        this.context = context;
        colorAccent = ContextCompat.getColor(context, R.color.colorAccent);
        TypedArray ta = context.getTheme().obtainStyledAttributes(new int[]{android.R.attr.textColorSecondary});
        try {
            colorText = ta.getColor(0, 0);
        } finally {
            ta.recycle();
        }
        listAll = listRule;
        listSelected = new ArrayList<>();
        listSelected.addAll(listRule);
    }

    @Override
    public void onBindViewHolder(final ViewHolder holder, int position) {
        // Get rule
        final Rule rule = listSelected.get(position);

        // Rule change listener
        CompoundButton.OnCheckedChangeListener cbListener = new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                String name;
                if (buttonView == holder.cbWifi) {
                    name = "wifi";
                    rule.wifi_blocked = isChecked;
                    rule.wifi_default = false;
                } else {
                    name = "other";
                    rule.other_blocked = isChecked;
                    rule.other_default = false;
                }
                Log.i(TAG, rule.info.packageName + ": " + name + "=" + isChecked);

                SharedPreferences prefs = context.getSharedPreferences(name, Context.MODE_PRIVATE);
                prefs.edit().putBoolean(rule.info.packageName, isChecked).apply();

                notifyDataSetChanged();

                BlackHoleService.reload(name, context);
            }
        };

        int color = rule.system ? colorAccent : colorText;
        if (rule.disabled)
            color = Color.argb(100, Color.red(color), Color.green(color), Color.blue(color));

        holder.ivIcon.setImageDrawable(rule.getIcon(context));
        holder.tvName.setText(rule.name);
        holder.tvName.setTextColor(color);
        holder.tvPackage.setText(rule.info.packageName);
        holder.tvPackage.setTextColor(color);

        holder.cbWifi.setOnCheckedChangeListener(null);
        holder.cbWifi.setChecked(rule.wifi_blocked);
        holder.cbWifi.setOnCheckedChangeListener(cbListener);
        holder.cbWifi.setAlpha(rule.wifi_default ? 0.4f : 1);

        holder.cbOther.setOnCheckedChangeListener(null);
        holder.cbOther.setChecked(rule.other_blocked);
        holder.cbOther.setOnCheckedChangeListener(cbListener);
        holder.cbOther.setAlpha(rule.other_default ? 0.4f : 1);

        holder.view.setOnLongClickListener(new View.OnLongClickListener() {
            @Override
            public boolean onLongClick(View view) {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
                SharedPreferences wifi = context.getSharedPreferences("wifi", Context.MODE_PRIVATE);
                SharedPreferences other = context.getSharedPreferences("other", Context.MODE_PRIVATE);

                wifi.edit().remove(rule.info.packageName).apply();
                other.edit().remove(rule.info.packageName).apply();

                rule.wifi_blocked = prefs.getBoolean("whitelist_wifi", true);
                rule.wifi_default = true;
                rule.other_blocked = prefs.getBoolean("whitelist_other", true);
                rule.other_default = true;

                notifyDataSetChanged();
                BlackHoleService.reload(null, context);
                return true;
            }
        });
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
                        if (rule.name.toLowerCase().contains(query))
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
