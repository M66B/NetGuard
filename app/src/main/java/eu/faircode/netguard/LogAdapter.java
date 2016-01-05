package eu.faircode.netguard;

import android.content.Context;
import android.database.Cursor;
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
        final long time = cursor.getLong(colTime);
        final String ip = cursor.getString(colIP);

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        TextView tvIP = (TextView) view.findViewById(R.id.tvIP);

        // Set values
        tvTime.setText(SimpleDateFormat.getDateTimeInstance(SimpleDateFormat.SHORT, SimpleDateFormat.MEDIUM).format(time));
        tvIP.setText(ip);
    }
}
