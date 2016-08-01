package eu.faircode.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2016 by Marcel Bokhorst (M66B)
*/

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.preference.PreferenceManager;
import android.support.v4.graphics.drawable.DrawableCompat;
import android.support.v4.view.ViewCompat;
import android.text.TextUtils;
import android.util.Log;
import android.util.TypedValue;
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

public class AdapterLog extends CursorAdapter {
    private static String TAG = "NetGuard.Log";

    private boolean resolve;
    private boolean organization;
    private int colID;
    private int colTime;
    private int colVersion;
    private int colProtocol;
    private int colFlags;
    private int colSAddr;
    private int colSPort;
    private int colDAddr;
    private int colDPort;
    private int colDName;
    private int colUid;
    private int colData;
    private int colAllowed;
    private int colConnection;
    private int colInteractive;
    private int colorOn;
    private int colorOff;
    private int iconSize;
    private InetAddress dns = null;
    private InetAddress vpn4 = null;
    private InetAddress vpn6 = null;

    public AdapterLog(Context context, Cursor cursor, boolean resolve, boolean organization) {
        super(context, cursor, 0);
        this.resolve = resolve;
        this.organization = organization;
        colID = cursor.getColumnIndex("ID");
        colTime = cursor.getColumnIndex("time");
        colVersion = cursor.getColumnIndex("version");
        colProtocol = cursor.getColumnIndex("protocol");
        colFlags = cursor.getColumnIndex("flags");
        colSAddr = cursor.getColumnIndex("saddr");
        colSPort = cursor.getColumnIndex("sport");
        colDAddr = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colDName = cursor.getColumnIndex("dname");
        colUid = cursor.getColumnIndex("uid");
        colData = cursor.getColumnIndex("data");
        colAllowed = cursor.getColumnIndex("allowed");
        colConnection = cursor.getColumnIndex("connection");
        colInteractive = cursor.getColumnIndex("interactive");

        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        colorOn = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        colorOff = tv.data;

        iconSize = Util.dips2pixels(24, context);

        try {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            dns = ServiceSinkhole.getDns(context).get(0);
            vpn4 = InetAddress.getByName(prefs.getString("vpn4", "10.1.10.1"));
            vpn6 = InetAddress.getByName(prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1"));
        } catch (UnknownHostException ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        }
    }

    public void setResolve(boolean resolve) {
        this.resolve = resolve;
    }

    public void setOrganization(boolean organization) {
        this.organization = organization;
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.log, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        final long id = cursor.getLong(colID);
        long time = cursor.getLong(colTime);
        int version = (cursor.isNull(colVersion) ? -1 : cursor.getInt(colVersion));
        int protocol = (cursor.isNull(colProtocol) ? -1 : cursor.getInt(colProtocol));
        String flags = cursor.getString(colFlags);
        String saddr = cursor.getString(colSAddr);
        int sport = (cursor.isNull(colSPort) ? -1 : cursor.getInt(colSPort));
        String daddr = cursor.getString(colDAddr);
        int dport = (cursor.isNull(colDPort) ? -1 : cursor.getInt(colDPort));
        String dname = (cursor.isNull(colDName) ? null : cursor.getString(colDName));
        int uid = (cursor.isNull(colUid) ? -1 : cursor.getInt(colUid));
        String data = cursor.getString(colData);
        int allowed = (cursor.isNull(colAllowed) ? -1 : cursor.getInt(colAllowed));
        int connection = (cursor.isNull(colConnection) ? -1 : cursor.getInt(colConnection));
        int interactive = (cursor.isNull(colInteractive) ? -1 : cursor.getInt(colInteractive));

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        TextView tvProtocol = (TextView) view.findViewById(R.id.tvProtocol);
        TextView tvFlags = (TextView) view.findViewById(R.id.tvFlags);
        TextView tvSAddr = (TextView) view.findViewById(R.id.tvSAddr);
        TextView tvSPort = (TextView) view.findViewById(R.id.tvSPort);
        final TextView tvDaddr = (TextView) view.findViewById(R.id.tvDAddr);
        TextView tvDPort = (TextView) view.findViewById(R.id.tvDPort);
        final TextView tvOrganization = (TextView) view.findViewById(R.id.tvOrganization);
        ImageView ivIcon = (ImageView) view.findViewById(R.id.ivIcon);
        TextView tvUid = (TextView) view.findViewById(R.id.tvUid);
        TextView tvData = (TextView) view.findViewById(R.id.tvData);
        ImageView ivConnection = (ImageView) view.findViewById(R.id.ivConnection);
        ImageView ivInteractive = (ImageView) view.findViewById(R.id.ivInteractive);

        // Show time
        tvTime.setText(new SimpleDateFormat("HH:mm:ss").format(time));

        // Show connection type
        if (connection <= 0)
            ivConnection.setImageResource(allowed > 0 ? R.drawable.host_allowed : R.drawable.host_blocked);
        else {
            if (allowed > 0)
                ivConnection.setImageResource(connection == 1 ? R.drawable.wifi_on : R.drawable.other_on);
            else
                ivConnection.setImageResource(connection == 1 ? R.drawable.wifi_off : R.drawable.other_off);
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            Drawable wrap = DrawableCompat.wrap(ivConnection.getDrawable());
            DrawableCompat.setTint(wrap, allowed > 0 ? colorOn : colorOff);
        }

        // Show if screen on
        if (interactive <= 0)
            ivInteractive.setImageDrawable(null);
        else {
            ivInteractive.setImageResource(R.drawable.screen_on);
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
                Drawable wrap = DrawableCompat.wrap(ivInteractive.getDrawable());
                DrawableCompat.setTint(wrap, colorOn);
            }
        }

        // Show protocol name
        tvProtocol.setText(Util.getProtocolName(protocol, version, false));

        // SHow TCP flags
        tvFlags.setText(flags);
        tvFlags.setVisibility(TextUtils.isEmpty(flags) ? View.GONE : View.VISIBLE);

        // Show source and destination port
        if (protocol == 6 || protocol == 17) {
            tvSPort.setText(sport < 0 ? "" : getKnownPort(sport));
            tvDPort.setText(dport < 0 ? "" : getKnownPort(dport));
        } else {
            tvSPort.setText(sport < 0 ? "" : Integer.toString(sport));
            tvDPort.setText(dport < 0 ? "" : Integer.toString(dport));
        }

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
            Picasso.with(context).load(uri).resize(iconSize, iconSize).into(ivIcon);
        }

        // https://android.googlesource.com/platform/system/core/+/master/include/private/android_filesystem_config.h
        uid = uid % 100000; // strip off user ID
        if (uid == -1)
            tvUid.setText("");
        else if (uid == 0)
            tvUid.setText(context.getString(R.string.title_root));
        else if (uid == 9999)
            tvUid.setText("-"); // nobody
        else
            tvUid.setText(Integer.toString(uid));

        // Show source address
        tvSAddr.setText(getKnownAddress(saddr));

        // Show destination address
        if (resolve && !isKnownAddress(daddr))
            if (dname == null) {
                tvDaddr.setText(daddr);
                new AsyncTask<String, Object, String>() {
                    @Override
                    protected void onPreExecute() {
                        ViewCompat.setHasTransientState(tvDaddr, true);
                    }

                    @Override
                    protected String doInBackground(String... args) {
                        try {
                            return InetAddress.getByName(args[0]).getHostName();
                        } catch (UnknownHostException ignored) {
                            return args[0];
                        }
                    }

                    @Override
                    protected void onPostExecute(String name) {
                        tvDaddr.setText(">" + name);
                        ViewCompat.setHasTransientState(tvDaddr, false);
                    }
                }.execute(daddr);
            } else
                tvDaddr.setText(dname);
        else
            tvDaddr.setText(getKnownAddress(daddr));

        // Show organization
        tvOrganization.setVisibility(View.GONE);
        if (organization) {
            if (!isKnownAddress(daddr))
                new AsyncTask<String, Object, String>() {
                    @Override
                    protected void onPreExecute() {
                        ViewCompat.setHasTransientState(tvOrganization, true);
                    }

                    @Override
                    protected String doInBackground(String... args) {
                        try {
                            return Util.getOrganization(args[0]);
                        } catch (Throwable ex) {
                            Log.w(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                            return null;
                        }
                    }

                    @Override
                    protected void onPostExecute(String organization) {
                        if (organization != null) {
                            tvOrganization.setText(organization);
                            tvOrganization.setVisibility(View.VISIBLE);
                        }
                        ViewCompat.setHasTransientState(tvOrganization, false);
                    }
                }.execute(daddr);
        }

        // Show extra data
        if (TextUtils.isEmpty(data)) {
            tvData.setText("");
            tvData.setVisibility(View.GONE);
        } else {
            tvData.setText(data);
            tvData.setVisibility(View.VISIBLE);
        }
    }

    public boolean isKnownAddress(String addr) {
        try {
            InetAddress a = InetAddress.getByName(addr);
            if (a.equals(dns) || a.equals(vpn4) || a.equals(vpn6))
                return true;
        } catch (UnknownHostException ignored) {
        }
        return false;
    }

    private String getKnownAddress(String addr) {
        try {
            InetAddress a = InetAddress.getByName(addr);
            if (a.equals(dns))
                return "dns";
            if (a.equals(vpn4) || a.equals(vpn6))
                return "vpn";
        } catch (UnknownHostException ignored) {
        }
        return addr;
    }

    private String getKnownPort(int port) {
        // https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Well-known_ports
        switch (port) {
            case 7:
                return "echo";
            case 25:
                return "smtp";
            case 53:
                return "dns";
            case 80:
                return "http";
            case 110:
                return "pop3";
            case 143:
                return "imap";
            case 443:
                return "https";
            case 465:
                return "smtps";
            case 993:
                return "imaps";
            case 995:
                return "pop3s";
            default:
                return Integer.toString(port);
        }
    }
}
