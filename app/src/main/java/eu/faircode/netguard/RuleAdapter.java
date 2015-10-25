package eu.faircode.netguard;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
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

    public RuleAdapter(List<Rule> listRule) {
        listAll = listRule;
        listSelected = new ArrayList<>();
        listSelected.addAll(listRule);
    }

    @Override
    public void onBindViewHolder(final ViewHolder holder, int position) {
        final Rule rule = listSelected.get(position);

        holder.ivIcon.setImageDrawable(rule.getIcon(holder.view.getContext()));
        holder.tvName.setText(rule.name);
        holder.tvPackage.setText(rule.info.packageName);

        CompoundButton.OnCheckedChangeListener cbListener = new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                String name;
                if (buttonView == holder.cbWifi) {
                    name = "wifi";
                    rule.wifi_blocked = isChecked;
                } else {
                    name = "other";
                    rule.other_blocked = isChecked;
                }
                Log.i(TAG, rule.info.packageName + ": " + name + "=" + isChecked);

                Context context = buttonView.getContext();

                SharedPreferences prefs = context.getSharedPreferences(name, Context.MODE_PRIVATE);
                prefs.edit().putBoolean(rule.info.packageName, isChecked).apply();

                Intent intent = new Intent(context, BlackHoleService.class);
                intent.putExtra(BlackHoleService.EXTRA_COMMAND, BlackHoleService.Command.reload);
                context.startService(intent);
            }
        };

        holder.cbWifi.setOnCheckedChangeListener(null);
        holder.cbWifi.setChecked(rule.wifi_blocked);
        holder.cbWifi.setOnCheckedChangeListener(cbListener);

        holder.cbOther.setOnCheckedChangeListener(null);
        holder.cbOther.setChecked(rule.other_blocked);
        holder.cbOther.setOnCheckedChangeListener(cbListener);
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
        return new ViewHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.rule, parent, false));
    }

    @Override
    public int getItemCount() {
        return listSelected.size();
    }
}
