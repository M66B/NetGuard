package eu.faircode.netguard;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.support.v7.widget.RecyclerView;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.TextView;

import java.util.List;

public class RuleAdapter extends RecyclerView.Adapter<RuleAdapter.ViewHolder> {
    private static final String TAG = "NetGuard.RuleAdapter";

    private List<Rule> listRule;

    public static class ViewHolder extends RecyclerView.ViewHolder {
        public TextView tvName;
        public TextView tvPackage;
        public CheckBox cbWifi;
        public CheckBox cbOther;

        public ViewHolder(View itemView) {
            super(itemView);
            this.tvName = (TextView) itemView.findViewById(R.id.tvName);
            this.tvPackage = (TextView) itemView.findViewById(R.id.tvPackage);
            this.cbWifi = (CheckBox) itemView.findViewById(R.id.cbWifi);
            this.cbOther = (CheckBox) itemView.findViewById(R.id.cbOther);
        }
    }

    public RuleAdapter(List<Rule> listRule) {
        this.listRule = listRule;
    }

    @Override
    public RuleAdapter.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.rule, parent, false);
        ViewHolder vh = new ViewHolder(v);
        return vh;
    }

    @Override
    public void onBindViewHolder(ViewHolder holder, int position) {
        final Rule rule = listRule.get(position);
        holder.tvName.setText(rule.name);
        holder.tvPackage.setText(rule.info.packageName);

        holder.cbWifi.setOnCheckedChangeListener(null);
        holder.cbWifi.setChecked(rule.wifi_blocked);
        holder.cbWifi.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean isChecked) {
                Context context = compoundButton.getContext();

                rule.wifi_blocked = isChecked;
                Log.i(TAG, rule.info.packageName + "=" + rule.wifi_blocked);

                SharedPreferences prefs = context.getSharedPreferences("wifi", Context.MODE_PRIVATE);
                prefs.edit().putBoolean(rule.info.packageName, rule.wifi_blocked).apply();

                if (PreferenceManager.getDefaultSharedPreferences(context).getBoolean("enabled", false)) {
                    Intent intent = new Intent(context, BlackHoleService.class);
                    intent.putExtra(BlackHoleService.EXTRA_START, true);
                    context.startService(intent);
                }
            }
        });

        holder.cbOther.setOnCheckedChangeListener(null);
        holder.cbOther.setChecked(rule.other_blocked);
        holder.cbOther.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean isChecked) {
                Context context = compoundButton.getContext();

                rule.other_blocked = isChecked;
                Log.i(TAG, rule.info.packageName + "=" + rule.other_blocked);

                SharedPreferences prefs = context.getSharedPreferences("other", Context.MODE_PRIVATE);
                prefs.edit().putBoolean(rule.info.packageName, rule.other_blocked).apply();

                if (PreferenceManager.getDefaultSharedPreferences(context).getBoolean("enabled", false)) {
                    Intent intent = new Intent(context, BlackHoleService.class);
                    intent.putExtra(BlackHoleService.EXTRA_START, true);
                    context.startService(intent);
                }
            }
        });
    }

    @Override
    public int getItemCount() {
        return this.listRule.size();
    }
}
