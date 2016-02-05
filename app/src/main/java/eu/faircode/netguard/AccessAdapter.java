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
import android.os.Build;
import android.support.v4.graphics.drawable.DrawableCompat;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import java.text.SimpleDateFormat;

public class AccessAdapter extends CursorAdapter {
    private static String TAG = "NetGuard.Access";

    private int colVersion;
    private int colProtocol;
    private int colDaddr;
    private int colDPort;
    private int colTime;
    private int colAllowed;
    private int colBlock;

    private int colorText;
    private int colorOn;
    private int colorOff;

    public AccessAdapter(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colVersion = cursor.getColumnIndex("version");
        colProtocol = cursor.getColumnIndex("protocol");
        colDaddr = cursor.getColumnIndex("daddr");
        colDPort = cursor.getColumnIndex("dport");
        colTime = cursor.getColumnIndex("time");
        colAllowed = cursor.getColumnIndex("allowed");
        colBlock = cursor.getColumnIndex("block");

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
        int version = cursor.getInt(colVersion);
        int protocol = cursor.getInt(colProtocol);
        String daddr = cursor.getString(colDaddr);
        int dport = cursor.getInt(colDPort);
        long time = cursor.getLong(colTime);
        int allowed = cursor.getInt(colAllowed);
        int block = cursor.getInt(colBlock);

        // Get views
        TextView tvTime = (TextView) view.findViewById(R.id.tvTime);
        ImageView ivBlock = (ImageView) view.findViewById(R.id.ivBlock);
        final TextView tvDest = (TextView) view.findViewById(R.id.tvDest);

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
                Util.getProtocolName(protocol, version, true) + " " +
                        daddr + (dport > 0 ? ":" + dport : ""));

        if (allowed < 0)
            tvDest.setTextColor(colorText);
        else if (allowed > 0)
            tvDest.setTextColor(colorOn);
        else
            tvDest.setTextColor(colorOff);
    }
}
