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
    private int colTime;
    private int colVersion;
    private int colIP;
    private int colProtocol;
    private int colUid;

    public LogAdapter(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colTime = cursor.getColumnIndex("time");
        colVersion = cursor.getColumnIndex("version");
        colIP = cursor.getColumnIndex("ip");
        colProtocol = cursor.getColumnIndex("protocol");
        colUid = cursor.getColumnIndex("uid");
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.log, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        long time = cursor.getLong(colTime);
        int version = (cursor.isNull(colVersion) ? -1 : cursor.getInt(colVersion));
        String ip = cursor.getString(colIP);
        int protocol = (cursor.isNull(colProtocol) ? -1 : cursor.getInt(colProtocol));
        final int uid = (cursor.isNull(colUid) ? -1 : cursor.getInt(colUid));
        final String whois = (ip.length() > 1 && ip.charAt(0) == '/' ? ip.substring(1) : ip);

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        TextView tvIP = (TextView) view.findViewById(R.id.tvIP);
        TextView tvProtocol = (TextView) view.findViewById(R.id.tvProtocol);
        TextView tvUid = (TextView) view.findViewById(R.id.tvUid);

        // Set values
        tvTime.setText(new SimpleDateFormat("dd").format(time) + " " +
                SimpleDateFormat.getTimeInstance(SimpleDateFormat.MEDIUM).format(time));

        tvIP.setText(whois);

        if (version == 4)
            if (protocol == IPv4Packet.IPv4Header.ICMP)
                tvProtocol.setText("ICMP");
            else if (protocol == IPv4Packet.IPv4Header.TCP)
                tvProtocol.setText("TCP");
            else if (protocol == IPv4Packet.IPv4Header.UDP)
                tvProtocol.setText("UDP");
            else
                tvProtocol.setText(protocol < 0 ? "" : Integer.toString(protocol));
        else
            tvProtocol.setText("");

        tvUid.setText(uid < 0 ? "" : Integer.toString(uid % 100000));

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

        tvUid.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                if (uid > 0) {
                    Intent main = new Intent(context, ActivityMain.class);
                    main.putExtra(ActivityMain.EXTRA_SEARCH, Integer.toString(uid));
                    context.startActivity(main);
                }
            }
        });
    }
}
