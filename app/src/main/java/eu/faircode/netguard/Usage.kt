package eu.faircode.netguard

import java.text.SimpleDateFormat
import java.util.*

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

   Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/   class Usage {
    var Time: Long = 0
    var Version = 0
    @JvmField
    var Protocol = 0
    @JvmField
    var DAddr: String? = null
    @JvmField
    var DPort = 0
    @JvmField
    var Uid = 0
    var Sent: Long = 0
    var Received: Long = 0
    override fun toString(): String {
        return formatter.format(Date(Time).time) +
                " v" + Version + " p" + Protocol +
                " " + DAddr + "/" + DPort +
                " uid " + Uid +
                " out " + Sent + " in " + Received
    }

    companion object {
        private val formatter = SimpleDateFormat.getDateTimeInstance()
    }
}