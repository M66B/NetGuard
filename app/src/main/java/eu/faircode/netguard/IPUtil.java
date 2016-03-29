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

import android.util.Log;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

public class IPUtil {
    private static final String TAG = "NetGuard.IPUtil";

    public static List<CIDR> toCIDR(String start, String end) throws UnknownHostException {
        return toCIDR(InetAddress.getByName(start), InetAddress.getByName(end));
    }

    public static List<CIDR> toCIDR(InetAddress start, InetAddress end) throws UnknownHostException {
        List<CIDR> listResult = new ArrayList<>();

        Log.i(TAG, "toCIDR(" + start.getHostAddress() + "," + end.getHostAddress() + ")");

        long from = inet2long(start);
        long to = inet2long(end);
        while (to >= from) {
            byte prefix = 32;
            while (prefix > 0) {
                long mask = (0xFFFFFFFF00000000L >> (prefix - 1)) % 0x0100000000L;
                if ((from & mask) != from)
                    break;
                prefix--;
            }

            byte max = (byte) (32 - Math.floor(Math.log(to - from + 1) / Math.log(2)));
            if (prefix < max)
                prefix = max;

            listResult.add(new CIDR(long2inet(from), prefix));

            from += Math.pow(2, (32 - prefix));
        }

        for (CIDR cidr : listResult)
            Log.i(TAG, cidr.toString());

        return listResult;
    }

    private static long inet2long(InetAddress addr) {
        long result = 0;
        for (byte b : addr.getAddress())
            result = result << 8 | (b & 0xFF);
        return result;
    }

    private static InetAddress long2inet(long addr) throws UnknownHostException {
        byte[] b = new byte[4];
        for (int i = b.length - 1; i >= 0; i--) {
            b[i] = (byte) (addr & 0xFF);
            addr = addr >> 8;
        }
        return InetAddress.getByAddress(b);
    }

    public static String minus1(String addr) throws UnknownHostException {
        return long2inet(inet2long(InetAddress.getByName(addr)) - 1).getHostAddress();
    }

    public static class CIDR {
        public InetAddress address;
        public int prefix;

        public CIDR(InetAddress address, int prefix) {
            this.address = address;
            this.prefix = prefix;
        }

        @Override
        public String toString() {
            return address.getHostAddress() + "/" + prefix;
        }
    }
}
