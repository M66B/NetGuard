package eu.faircode.netguard;

import android.content.Context;
import android.database.Cursor;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CheckBox;
import android.widget.CursorAdapter;
import android.widget.TextView;

import java.text.SimpleDateFormat;

public class AccessAdapter extends CursorAdapter {
    private static String TAG = "NetGuard.Access";

    private int colDaddr;
    private int colDPort;
    private int colDName;
    private int colTime;
    private int colAllowed;

    public AccessAdapter(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colDaddr = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colDName = cursor.getColumnIndex("dname");
        colTime = cursor.getColumnIndex("time");
        colAllowed = cursor.getColumnIndex("allowed");
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.access, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        String daddr = cursor.getString(colDaddr);
        int dport = (cursor.isNull(colDPort) ? -1 : cursor.getInt(colDPort));
        String dname = (cursor.isNull(colDName) ? null : cursor.getString(colDName));
        long time = cursor.getLong(colTime);
        int allowed = cursor.getInt(colAllowed);

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        CheckBox cbIp = (CheckBox) view.findViewById(R.id.cbIp);
        final TextView tvDest = (TextView) view.findViewById(R.id.tvDest);

        // Set values
        tvTime.setText(new SimpleDateFormat("HH:mm:ss").format(time));
        cbIp.setChecked(allowed != 0);
        tvDest.setText((dname == null ? daddr : dname) + (dport > 0 ? ":" + dport : ""));
    }
}
