package eu.faircode.netguard;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.TextView;

import java.text.SimpleDateFormat;

public class LogAdapter extends CursorAdapter {
    private static final String TAG = "Netguard.Log";

    private Context mContext;
    private int colTime;
    private int colIP;

    public LogAdapter(Context context, Cursor cursor) {
        super(context, cursor, 0);
        mContext = context;
        colTime = cursor.getColumnIndex("time");
        colIP = cursor.getColumnIndex("ip");
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.log, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        long time = cursor.getLong(colTime);
        String ip = cursor.getString(colIP);

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        TextView tvIP = (TextView) view.findViewById(R.id.tvIP);

        // Set values
        tvTime.setText(SimpleDateFormat.getDateTimeInstance(SimpleDateFormat.SHORT, SimpleDateFormat.MEDIUM).format(time));
        tvIP.setText(ip);

        final String whois = (ip.length() > 1 && ip.charAt(0) == '/' ? ip.substring(1) : ip);
        tvIP.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (!TextUtils.isEmpty(whois)) {
                    Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://whois.domaintools.com/" + whois));
                    if (context.getPackageManager().resolveActivity(intent, 0) != null)
                        context.startActivity(intent);
                }
            }
        });
    }
}
