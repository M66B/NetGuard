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
    private int colTime;
    private int colBlock;

    public AccessAdapter(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colDaddr = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colTime = cursor.getColumnIndex("time");
        colBlock = cursor.getColumnIndex("block");
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
        long time = cursor.getLong(colTime);
        int block = cursor.getInt(colBlock);

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        CheckBox cbBlock = (CheckBox) view.findViewById(R.id.cbBlock);
        final TextView tvDest = (TextView) view.findViewById(R.id.tvDest);

        // Set values
        tvTime.setText(new SimpleDateFormat("HH:mm:ss").format(time));
        cbBlock.setVisibility(block < 0 ? View.INVISIBLE : View.VISIBLE);
        cbBlock.setChecked(block > 0);
        tvDest.setText(daddr + (dport > 0 ? ":" + dport : ""));
    }
}
