package eu.faircode.netguard;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import com.squareup.picasso.Picasso;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;

public class LogAdapter extends CursorAdapter {
    private static String TAG = "NetGuard.Log";

    private boolean resolve;
    private int colTime;
    private int colVersion;
    private int colProtocol;
    private int colFlags;
    private int colSource;
    private int colSPort;
    private int colDest;
    private int colDPort;
    private int colUid;
    private int colAllowed;
    private int colConnection;
    private int colInteractive;
    private InetAddress vpn4 = null;
    private InetAddress vpn6 = null;
    private Map<String, String> mapIPHost = new HashMap<String, String>();

    public LogAdapter(Context context, Cursor cursor, boolean resolve) {
        super(context, cursor, 0);
        this.resolve = resolve;
        colTime = cursor.getColumnIndex("time");
        colVersion = cursor.getColumnIndex("version");
        colProtocol = cursor.getColumnIndex("protocol");
        colFlags = cursor.getColumnIndex("flags");
        colSource = cursor.getColumnIndex("saddr");
        colSPort = cursor.getColumnIndex("sport");
        colDest = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colUid = cursor.getColumnIndex("uid");
        colAllowed = cursor.getColumnIndex("allowed");
        colConnection = cursor.getColumnIndex("connection");
        colInteractive = cursor.getColumnIndex("interactive");

        try {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            vpn4 = InetAddress.getByName(prefs.getString("vpn4", "10.1.10.1"));
            vpn6 = InetAddress.getByName(prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1"));
        } catch (UnknownHostException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
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
        int protocol = (cursor.isNull(colProtocol) ? -1 : cursor.getInt(colProtocol));
        String flags = cursor.getString(colFlags);
        String source = cursor.getString(colSource);
        int sport = (cursor.isNull(colSPort) ? -1 : cursor.getInt(colSPort));
        final String dest = cursor.getString(colDest);
        int dport = (cursor.isNull(colDPort) ? -1 : cursor.getInt(colDPort));
        int uid = (cursor.isNull(colUid) ? -1 : cursor.getInt(colUid));
        int allowed = (cursor.isNull(colAllowed) ? -1 : cursor.getInt(colAllowed));
        int connection = (cursor.isNull(colConnection) ? -1 : cursor.getInt(colConnection));
        int interactive = (cursor.isNull(colInteractive) ? -1 : cursor.getInt(colInteractive));

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        TextView tvProtocol = (TextView) view.findViewById(R.id.tvProtocol);
        TextView tvFlags = (TextView) view.findViewById(R.id.tvFlags);
        final TextView tvSource = (TextView) view.findViewById(R.id.tvSource);
        TextView tvSPort = (TextView) view.findViewById(R.id.tvSPort);
        final TextView tvDest = (TextView) view.findViewById(R.id.tvDest);
        TextView tvDPort = (TextView) view.findViewById(R.id.tvDPort);
        ImageView ivIcon = (ImageView) view.findViewById(R.id.ivIcon);
        TextView tvUid = (TextView) view.findViewById(R.id.tvUid);
        ImageView ivConnection = (ImageView) view.findViewById(R.id.ivConnection);
        ImageView ivInteractive = (ImageView) view.findViewById(R.id.ivInteractive);

        // Set values
        tvTime.setText(new SimpleDateFormat("HH:mm:ss").format(time));

        if (connection <= 0)
            ivConnection.setImageDrawable(null);
        else {
            if (allowed > 0)
                ivConnection.setImageResource(connection == 1 ? R.drawable.wifi_on : R.drawable.other_on);
            else
                ivConnection.setImageResource(connection == 1 ? R.drawable.wifi_off : R.drawable.other_off);
        }

        if (interactive <= 0)
            ivInteractive.setImageDrawable(null);
        else
            ivInteractive.setImageResource(R.drawable.screen_on);

        // https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        if (protocol == 0) // HOPOPT
            tvProtocol.setText("HOPO" + version);
        else if (protocol == 1) // ICMP
            tvProtocol.setText("ICMP" + version);
        else if (protocol == 6) // TCP
            tvProtocol.setText("TCP" + version);
        else if (protocol == 17) // UDP
            tvProtocol.setText("UDP" + version);
        else
            tvProtocol.setText(protocol < 0 ? "" : "P" + Integer.toString(protocol) + "V" + version);

        tvFlags.setText(flags);

        tvSPort.setText(sport < 0 ? "" : getKnownPort(sport));
        tvDPort.setText(dport < 0 ? "" : getKnownPort(dport));

        // Application icon
        ApplicationInfo info = null;
        PackageManager pm = context.getPackageManager();
        String[] pkg = pm.getPackagesForUid(uid);
        if (pkg != null && pkg.length > 0)
            try {
                info = pm.getApplicationInfo(pkg[0], 0);
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        if (info == null)
            ivIcon.setImageDrawable(null);
        else if (info.icon == 0)
            Picasso.with(context).load(android.R.drawable.sym_def_app_icon).into(ivIcon);
        else {
            Uri uri = Uri.parse("android.resource://" + info.packageName + "/" + info.icon);
            Picasso.with(context).load(uri).into(ivIcon);
        }

        // https://android.googlesource.com/platform/system/core/+/master/include/private/android_filesystem_config.h
        uid = uid % 100000; // strip off user ID
        if (uid == -1)
            tvUid.setText("");
        else if (uid == 0)
            tvUid.setText("root");
        else if (uid == 9999)
            tvUid.setText("-"); // nobody
        else
            tvUid.setText(Integer.toString(uid));

        // TODO resolve source when inbound
        tvSource.setText(getKnownAddress(source));

        if (resolve && !isKnownAddress(dest))
            synchronized (mapIPHost) {
                if (mapIPHost.containsKey(dest))
                    tvDest.setText(mapIPHost.get(dest));
                else {
                    tvDest.setText(dest);
                    new AsyncTask<String, Object, String>() {
                        @Override
                        protected String doInBackground(String... args) {
                            try {
                                // This requires internet permission
                                return InetAddress.getByName(args[0]).getHostName();
                            } catch (UnknownHostException ignored) {
                                return dest;
                            }
                        }

                        @Override
                        protected void onPostExecute(String host) {
                            synchronized (mapIPHost) {
                                if (!mapIPHost.containsKey(host))
                                    mapIPHost.put(host, host);
                            }
                            tvDest.setText(host);
                        }
                    }.execute(dest);
                }
            }
        else
            tvDest.setText(getKnownAddress(dest));
    }

    public boolean isKnownAddress(String addr) {
        try {
            InetAddress a = InetAddress.getByName(addr);
            if (a.equals(vpn4) || a.equals(vpn6))
                return true;
        } catch (UnknownHostException ignored) {
        }
        return false;
    }

    private String getKnownAddress(String addr) {
        try {
            InetAddress a = InetAddress.getByName(addr);
            if (a.equals(vpn4) || a.equals(vpn6))
                return "vpn";
        } catch (UnknownHostException ignored) {
        }
        return addr;
    }

    private String getKnownPort(int port) {
        if (port == 53)
            return "dns";
        else if (port == 80)
            return "http";
        else if (port == 443)
            return "https";
        return Integer.toString(port);
    }
}
