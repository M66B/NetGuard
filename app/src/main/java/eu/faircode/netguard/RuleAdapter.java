package eu.faircode.netguard;

import android.content.Context;
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
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.Filter;
import android.widget.Filterable;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

public class RuleAdapter extends RecyclerView.Adapter<RuleAdapter.ViewHolder> implements Filterable {
    private static final String TAG = "NetGuard.Adapter";

    private Context context;
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
        public TextView tvPackage;
        public CheckBox cbWifi;
        public CheckBox cbOther;
        public LinearLayout llAttributes;
        public ImageView ivUsing;
        public LinearLayout llConfiguration;
        public CheckBox cbUsing;
        public Button btnLaunch;

        public ViewHolder(View itemView) {
            super(itemView);
            view = itemView;
            llApplication = (LinearLayout) itemView.findViewById(R.id.llApplication);
            ivIcon = (ImageView) itemView.findViewById(R.id.ivIcon);
            ivExpander = (ImageView) itemView.findViewById(R.id.ivExpander);
            tvName = (TextView) itemView.findViewById(R.id.tvName);
            tvPackage = (TextView) itemView.findViewById(R.id.tvPackage);
            cbWifi = (CheckBox) itemView.findViewById(R.id.cbWifi);
            cbOther = (CheckBox) itemView.findViewById(R.id.cbOther);
            llAttributes = (LinearLayout) itemView.findViewById(R.id.llAttributes);
            ivUsing = (ImageView) itemView.findViewById(R.id.ivUsing);
            llConfiguration = (LinearLayout) itemView.findViewById(R.id.llConfiguration);
            cbUsing = (CheckBox) itemView.findViewById(R.id.cbUsing);
            btnLaunch = (Button) itemView.findViewById(R.id.btnLaunch);
        }
    }

    public RuleAdapter(Context context) {
        this.context = context;
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
                String network;
                if (buttonView == holder.cbWifi) {
                    network = "wifi";
                    rule.wifi_blocked = isChecked;
                } else {
                    network = "other";
                    rule.other_blocked = isChecked;
                }
                Log.i(TAG, rule.info.packageName + ": " + network + "=" + isChecked);

                // Store rule
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
                SharedPreferences rules = context.getSharedPreferences(network, Context.MODE_PRIVATE);
                if (isChecked == prefs.getBoolean("whitelist_" + network, true)) {
                    Log.i(TAG, "Removing " + rule.info.packageName + " " + network);
                    rules.edit().remove(rule.info.packageName).apply();
                } else {
                    Log.i(TAG, "Setting " + rule.info.packageName + " " + network + "=" + isChecked);
                    rules.edit().putBoolean(rule.info.packageName, isChecked).apply();
                }

                // Update UI
                notifyItemChanged(position);

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

        int color = rule.system ? colorAccent : colorText;
        if (rule.disabled)
            color = Color.argb(100, Color.red(color), Color.green(color), Color.blue(color));

        holder.ivIcon.setImageDrawable(rule.getIcon(context));
        holder.ivExpander.setImageResource(rule.attributes ? android.R.drawable.arrow_up_float : android.R.drawable.arrow_down_float);
        holder.llApplication.setOnClickListener(llListener);
        holder.tvName.setText(rule.name);
        holder.tvName.setTextColor(color);
        holder.tvPackage.setText(rule.info.packageName);
        holder.tvPackage.setTextColor(color);

        holder.cbWifi.setOnCheckedChangeListener(null);
        holder.cbWifi.setChecked(rule.wifi_blocked);
        holder.cbWifi.setOnCheckedChangeListener(cbListener);

        holder.cbOther.setOnCheckedChangeListener(null);
        holder.cbOther.setChecked(rule.other_blocked);
        holder.cbOther.setOnCheckedChangeListener(cbListener);

        holder.llAttributes.setOnClickListener(llListener);
        holder.ivUsing.setVisibility(rule.unused && (rule.wifi_blocked || rule.other_blocked) ? View.VISIBLE : View.INVISIBLE);

        holder.llConfiguration.setVisibility(rule.attributes ? View.VISIBLE : View.GONE);
        holder.cbUsing.setOnCheckedChangeListener(null);
        holder.cbUsing.setChecked(rule.unused);
        holder.cbUsing.setEnabled(rule.wifi_blocked || rule.other_blocked);

        holder.cbUsing.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                // Update rule
                rule.unused = isChecked;

                // Store rule
                SharedPreferences unused = context.getSharedPreferences("unused", Context.MODE_PRIVATE);
                if (rule.unused)
                    unused.edit().putBoolean(rule.info.packageName, true).apply();
                else
                    unused.edit().remove(rule.info.packageName).apply();

                // Update UI
                notifyItemChanged(position);

                // Apply updated rule
                SinkholeService.reload(null, context);
            }
        });

        holder.btnLaunch.setEnabled(rule.intent != null);
        holder.btnLaunch.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                context.startActivity(rule.intent);
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
                        if (rule.info.packageName.toLowerCase().contains(query) ||
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
