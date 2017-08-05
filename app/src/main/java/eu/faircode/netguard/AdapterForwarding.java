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

    Copyright 2015-2017 by Marcel Bokhorst (M66B)
*/

import android.content.Context;
import android.database.Cursor;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.TextView;

public class AdapterForwarding extends CursorAdapter {
    private int colProtocol;
    private int colDPort;
    private int colRAddr;
    private int colRPort;
    private int colRUid;

    public AdapterForwarding(Context context, Cursor cursor) {
        super(context, cursor, 0);
        colProtocol = cursor.getColumnIndex("protocol");
        colDPort = cursor.getColumnIndex("dport");
        colRAddr = cursor.getColumnIndex("raddr");
        colRPort = cursor.getColumnIndex("rport");
        colRUid = cursor.getColumnIndex("ruid");
    }

    @Override
    public View newView(Context context, Cursor cursor, ViewGroup parent) {
        return LayoutInflater.from(context).inflate(R.layout.forward, parent, false);
    }

    @Override
    public void bindView(final View view, final Context context, final Cursor cursor) {
        // Get values
        int protocol = cursor.getInt(colProtocol);
        int dport = cursor.getInt(colDPort);
        String raddr = cursor.getString(colRAddr);
        int rport = cursor.getInt(colRPort);
        int ruid = cursor.getInt(colRUid);

        // Get views
        TextView tvProtocol = view.findViewById(R.id.tvProtocol);
        TextView tvDPort = view.findViewById(R.id.tvDPort);
        TextView tvRAddr = view.findViewById(R.id.tvRAddr);
        TextView tvRPort = view.findViewById(R.id.tvRPort);
        TextView tvRUid = view.findViewById(R.id.tvRUid);

        tvProtocol.setText(Util.getProtocolName(protocol, 0, false));
        tvDPort.setText(Integer.toString(dport));
        tvRAddr.setText(raddr);
        tvRPort.setText(Integer.toString(rport));
        tvRUid.setText(TextUtils.join(", ", Util.getApplicationNames(ruid, context)));
    }
}
