package eu.faircode.netguard;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import com.squareup.picasso.Picasso;

import java.text.SimpleDateFormat;

public class LogAdapter extends CursorAdapter {
    private int colTime;
    private int colVersion;
    private int colIP;
    private int colProtocol;
    private int colPort;
    private int colFlags;
    private int colUid;

    public LogAdapter(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colTime = cursor.getColumnIndex("time");
        colVersion = cursor.getColumnIndex("version");
        colIP = cursor.getColumnIndex("ip");
        colProtocol = cursor.getColumnIndex("protocol");
        colPort = cursor.getColumnIndex("port");
        colFlags = cursor.getColumnIndex("flags");
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
        int port = (cursor.isNull(colPort) ? -1 : cursor.getInt(colPort));
        String flags = cursor.getString(colFlags);
        final int uid = (cursor.isNull(colUid) ? -1 : cursor.getInt(colUid));

        final String whois = (ip.length() > 1 && ip.charAt(0) == '/' ? ip.substring(1) : ip);

        // Get views
        ImageView ivIcon = (ImageView) view.findViewById(R.id.ivIcon);
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        TextView tvIP = (TextView) view.findViewById(R.id.tvIP);
        TextView tvProtocol = (TextView) view.findViewById(R.id.tvProtocol);
        TextView tvPort = (TextView) view.findViewById(R.id.tvPort);
        TextView tvFlags = (TextView) view.findViewById(R.id.tvFlags);
        TextView tvUid = (TextView) view.findViewById(R.id.tvUid);

        // Application icon
        ApplicationInfo info = null;
        PackageManager pm = context.getPackageManager();
        String[] pkg = pm.getPackagesForUid(uid);
        if (pkg != null && pkg.length > 0)
            try {
                info = pm.getApplicationInfo(pkg[0], 0);
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        if (info == null || info.icon == 0)
            ivIcon.setImageDrawable(null);
        else {
            Uri uri = Uri.parse("android.resource://" + info.packageName + "/" + info.icon);
            Picasso.with(context).load(uri).into(ivIcon);
        }

        // Set values
        tvTime.setText(new SimpleDateFormat("dd").format(time) + " " +
                SimpleDateFormat.getTimeInstance(SimpleDateFormat.MEDIUM).format(time));

        tvIP.setText(whois);

        if (version == 4)
            if (protocol == IPv4Packet.IPv4Header.ICMP)
                tvProtocol.setText("I");
            else if (protocol == IPv4Packet.IPv4Header.TCP)
                tvProtocol.setText("T");
            else if (protocol == IPv4Packet.IPv4Header.UDP)
                tvProtocol.setText("U");
            else
                tvProtocol.setText(protocol < 0 ? "" : Integer.toString(protocol));
        else
            tvProtocol.setText("");

        tvPort.setText(port < 0 ? "" : Integer.toString(port));
        tvFlags.setText(flags);
        tvUid.setText(uid < 0 ? "" : Integer.toString(uid % 100000));
    }
}
