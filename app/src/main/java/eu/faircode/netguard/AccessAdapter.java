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
import android.database.Cursor;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ImageView;
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
        ImageView ivBlock = (ImageView) view.findViewById(R.id.ivBlock);
        final TextView tvDest = (TextView) view.findViewById(R.id.tvDest);

        // Set values
        tvTime.setText(new SimpleDateFormat("dd HH:mm").format(time));
        if (block < 0)
            ivBlock.setImageDrawable(null);
        else
            ivBlock.setImageResource(block > 0 ? R.drawable.host_blocked : R.drawable.host_allowed);
        tvDest.setText(daddr + (dport > 0 ? ":" + dport : ""));
    }
}
