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
import android.content.res.TypedArray;
import android.database.Cursor;
import android.graphics.drawable.Drawable;
import android.os.AsyncTask;
import android.os.Build;
import android.support.v4.graphics.drawable.DrawableCompat;
import android.support.v4.view.ViewCompat;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;

public class AdapterAccess extends CursorAdapter {
    private static String TAG = "NetGuard.Access";

    private int colID;
    private int colVersion;
    private int colProtocol;
    private int colDaddr;
    private int colDPort;
    private int colTime;
    private int colAllowed;
    private int colBlock;
    private int colSent;
    private int colReceived;
    private int colConnections;

    private int colorText;
    private int colorOn;
    private int colorOff;

    public AdapterAccess(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colID = cursor.getColumnIndex("ID");
        colVersion = cursor.getColumnIndex("version");
        colProtocol = cursor.getColumnIndex("protocol");
        colDaddr = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colTime = cursor.getColumnIndex("time");
        colAllowed = cursor.getColumnIndex("allowed");
        colBlock = cursor.getColumnIndex("block");
        colSent = cursor.getColumnIndex("sent");
        colReceived = cursor.getColumnIndex("received");
        colConnections = cursor.getColumnIndex("connections");

        TypedArray ta = context.getTheme().obtainStyledAttributes(new int[]{android.R.attr.textColorSecondary});
        try {
            colorText = ta.getColor(0, 0);
        } finally {
            ta.recycle();
        }

        TypedValue tv = new TypedValue();
        context.getTheme().resolveAttribute(R.attr.colorOn, tv, true);
        colorOn = tv.data;
        context.getTheme().resolveAttribute(R.attr.colorOff, tv, true);
        colorOff = tv.data;
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.access, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        final long id = cursor.getLong(colID);
        final int version = cursor.getInt(colVersion);
        final int protocol = cursor.getInt(colProtocol);
        final String daddr = cursor.getString(colDaddr);
        final int dport = cursor.getInt(colDPort);
        long time = cursor.getLong(colTime);
        int allowed = cursor.getInt(colAllowed);
        int block = cursor.getInt(colBlock);
        long sent = cursor.isNull(colSent) ? -1 : cursor.getLong(colSent);
        long received = cursor.isNull(colReceived) ? -1 : cursor.getLong(colReceived);
        int connections = cursor.isNull(colConnections) ? -1 : cursor.getInt(colConnections);

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        ImageView ivBlock = (ImageView) view.findViewById(R.id.ivBlock);
        final TextView tvDest = (TextView) view.findViewById(R.id.tvDest);
        LinearLayout llTraffic = (LinearLayout) view.findViewById(R.id.llTraffic);
        TextView tvConnections = (TextView) view.findViewById(R.id.tvConnections);
        TextView tvTraffic = (TextView) view.findViewById(R.id.tvTraffic);

        // Set values
        tvTime.setText(new SimpleDateFormat("dd HH:mm").format(time));
        if (block < 0)
            ivBlock.setImageDrawable(null);
        else {
            ivBlock.setImageResource(block > 0 ? R.drawable.host_blocked : R.drawable.host_allowed);
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
                Drawable wrap = DrawableCompat.wrap(ivBlock.getDrawable());
                DrawableCompat.setTint(wrap, block > 0 ? colorOff : colorOn);
            }
        }

        tvDest.setText(
                Util.getProtocolName(protocol, version, true) +
                        " " + daddr + (dport > 0 ? "/" + dport : ""));

        if (Util.isNumericAddress(daddr))
            new AsyncTask<String, Object, String>() {
                @Override
                protected void onPreExecute() {
                    ViewCompat.setHasTransientState(tvDest, true);
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
                protected void onPostExecute(String addr) {
                    tvDest.setText(
                            Util.getProtocolName(protocol, version, true) +
                                    " >" + addr + (dport > 0 ? "/" + dport : ""));
                    ViewCompat.setHasTransientState(tvDest, false);
                }
            }.execute(daddr);

        if (allowed < 0)
            tvDest.setTextColor(colorText);
        else if (allowed > 0)
            tvDest.setTextColor(colorOn);
        else
            tvDest.setTextColor(colorOff);

        llTraffic.setVisibility(connections > 0 || sent > 0 || received > 0 ? View.VISIBLE : View.GONE);
        if (connections > 0)
            tvConnections.setText(context.getString(R.string.msg_count, connections));

        if (sent > 1024 * 1204 * 1024L || received > 1024 * 1024 * 1024L)
            tvTraffic.setText(context.getString(R.string.msg_gb,
                    (sent > 0 ? sent / (1024 * 1024 * 1024f) : 0),
                    (received > 0 ? received / (1024 * 1024 * 1024f) : 0)));
        else if (sent > 1204 * 1024L || received > 1024 * 1024L)
            tvTraffic.setText(context.getString(R.string.msg_mb,
                    (sent > 0 ? sent / (1024 * 1024f) : 0),
                    (received > 0 ? received / (1024 * 1024f) : 0)));
        else
            tvTraffic.setText(context.getString(R.string.msg_kb,
                    (sent > 0 ? sent / 1024f : 0),
                    (received > 0 ? received / 1024f : 0)));
    }
}
