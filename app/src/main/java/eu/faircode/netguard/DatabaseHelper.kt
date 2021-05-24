package eu.faircode.netguard

import android.content.ContentValues
import android.content.Context
import android.content.SharedPreferences
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteDoneException
import android.database.sqlite.SQLiteOpenHelper
import android.os.Handler
import android.os.HandlerThread
import android.os.Message
import android.util.Log
import androidx.preference.PreferenceManager
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.locks.ReentrantReadWriteLock

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
*/   class DatabaseHelper private constructor(context: Context) : SQLiteOpenHelper(context, DB_NAME, null, DB_VERSION) {
    private val prefs: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
    private val lock = ReentrantReadWriteLock(true)

    companion object {
        private const val TAG = "NetGuard.Database"
        private const val DB_NAME = "Netguard"
        private const val DB_VERSION = 21
        private var once = true
        private val logChangedListeners: MutableList<LogChangedListener> = ArrayList()
        private val accessChangedListeners: MutableList<AccessChangedListener> = ArrayList()
        private val forwardChangedListeners: MutableList<ForwardChangedListener> = ArrayList()
        private var hthread: HandlerThread? = null
        private var handler: Handler? = null
        private val mapUidHosts: MutableMap<Int, Long> = HashMap()
        private const val MSG_LOG = 1
        private const val MSG_ACCESS = 2
        private const val MSG_FORWARD = 3
        private var dh: DatabaseHelper? = null
        @JvmStatic
        fun getInstance(context: Context): DatabaseHelper? {
            if (dh == null) dh = DatabaseHelper(context.applicationContext)
            return dh
        }

        fun clearCache() {
            synchronized(mapUidHosts) { mapUidHosts.clear() }
        }

        private fun handleChangedNotification(msg: Message) {
            // Batch notifications
            try {
                Thread.sleep(1000)
                if (handler!!.hasMessages(msg.what)) handler!!.removeMessages(msg.what)
            } catch (ignored: InterruptedException) {
            }

            // Notify listeners
            if (msg.what == MSG_LOG) {
                for (listener in logChangedListeners) try {
                    listener.onChanged()
                } catch (ex: Throwable) {
                    Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                }
            } else if (msg.what == MSG_ACCESS) {
                for (listener in accessChangedListeners) try {
                    listener.onChanged()
                } catch (ex: Throwable) {
                    Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                }
            } else if (msg.what == MSG_FORWARD) {
                for (listener in forwardChangedListeners) try {
                    listener.onChanged()
                } catch (ex: Throwable) {
                    Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
                }
            }
        }

        init {
            hthread = HandlerThread("DatabaseHelper")
            hthread!!.start()
            handler = object : Handler(hthread!!.looper) {
                override fun handleMessage(msg: Message) {
                    handleChangedNotification(msg)
                }
            }
        }
    }

    override fun close() {
        Log.w(TAG, "Database is being closed")
    }

    override fun onCreate(db: SQLiteDatabase) {
        Log.i(TAG, "Creating database " + DB_NAME + " version " + DB_VERSION)
        createTableLog(db)
        createTableAccess(db)
        createTableDns(db)
        createTableForward(db)
        createTableApp(db)
    }

    override fun onConfigure(db: SQLiteDatabase) {
        db.enableWriteAheadLogging()
        super.onConfigure(db)
    }

    private fun createTableLog(db: SQLiteDatabase) {
        Log.i(TAG, "Creating log table")
        db.execSQL("CREATE TABLE log (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", time INTEGER NOT NULL" +
                ", version INTEGER" +
                ", protocol INTEGER" +
                ", flags TEXT" +
                ", saddr TEXT" +
                ", sport INTEGER" +
                ", daddr TEXT" +
                ", dport INTEGER" +
                ", dname TEXT" +
                ", uid INTEGER" +
                ", data TEXT" +
                ", allowed INTEGER" +
                ", connection INTEGER" +
                ", interactive INTEGER" +
                ");")
        db.execSQL("CREATE INDEX idx_log_time ON log(time)")
        db.execSQL("CREATE INDEX idx_log_dest ON log(daddr)")
        db.execSQL("CREATE INDEX idx_log_dname ON log(dname)")
        db.execSQL("CREATE INDEX idx_log_dport ON log(dport)")
        db.execSQL("CREATE INDEX idx_log_uid ON log(uid)")
    }

    private fun createTableAccess(db: SQLiteDatabase) {
        Log.i(TAG, "Creating access table")
        db.execSQL("CREATE TABLE access (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", uid INTEGER NOT NULL" +
                ", version INTEGER NOT NULL" +
                ", protocol INTEGER NOT NULL" +
                ", daddr TEXT NOT NULL" +
                ", dport INTEGER NOT NULL" +
                ", time INTEGER NOT NULL" +
                ", allowed INTEGER" +
                ", block INTEGER NOT NULL" +
                ", sent INTEGER" +
                ", received INTEGER" +
                ", connections INTEGER" +
                ");")
        db.execSQL("CREATE UNIQUE INDEX idx_access ON access(uid, version, protocol, daddr, dport)")
        db.execSQL("CREATE INDEX idx_access_daddr ON access(daddr)")
        db.execSQL("CREATE INDEX idx_access_block ON access(block)")
    }

    private fun createTableDns(db: SQLiteDatabase) {
        Log.i(TAG, "Creating dns table")
        db.execSQL("CREATE TABLE dns (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", time INTEGER NOT NULL" +
                ", qname TEXT NOT NULL" +
                ", aname TEXT NOT NULL" +
                ", resource TEXT NOT NULL" +
                ", ttl INTEGER" +
                ");")
        db.execSQL("CREATE UNIQUE INDEX idx_dns ON dns(qname, aname, resource)")
        db.execSQL("CREATE INDEX idx_dns_resource ON dns(resource)")
    }

    private fun createTableForward(db: SQLiteDatabase) {
        Log.i(TAG, "Creating forward table")
        db.execSQL("CREATE TABLE forward (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", protocol INTEGER NOT NULL" +
                ", dport INTEGER NOT NULL" +
                ", raddr TEXT NOT NULL" +
                ", rport INTEGER NOT NULL" +
                ", ruid INTEGER NOT NULL" +
                ");")
        db.execSQL("CREATE UNIQUE INDEX idx_forward ON forward(protocol, dport)")
    }

    private fun createTableApp(db: SQLiteDatabase) {
        Log.i(TAG, "Creating app table")
        db.execSQL("CREATE TABLE app (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", package TEXT" +
                ", label TEXT" +
                ", system INTEGER  NOT NULL" +
                ", internet INTEGER NOT NULL" +
                ", enabled INTEGER NOT NULL" +
                ");")
        db.execSQL("CREATE UNIQUE INDEX idx_package ON app(package)")
    }

    private fun columnExists(db: SQLiteDatabase, table: String, column: String): Boolean {
        var cursor: Cursor? = null
        return try {
            cursor = db.rawQuery("SELECT * FROM $table LIMIT 0", null)
            cursor.getColumnIndex(column) >= 0
        } catch (ex: Throwable) {
            Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
            false
        } finally {
            cursor?.close()
        }
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        var oldVersion = oldVersion
        Log.i(TAG, DB_NAME + " upgrading from version " + oldVersion + " to " + newVersion)
        db.beginTransaction()
        try {
            if (oldVersion < 2) {
                if (!columnExists(db, "log", "version")) db.execSQL("ALTER TABLE log ADD COLUMN version INTEGER")
                if (!columnExists(db, "log", "protocol")) db.execSQL("ALTER TABLE log ADD COLUMN protocol INTEGER")
                if (!columnExists(db, "log", "uid")) db.execSQL("ALTER TABLE log ADD COLUMN uid INTEGER")
                oldVersion = 2
            }
            if (oldVersion < 3) {
                if (!columnExists(db, "log", "port")) db.execSQL("ALTER TABLE log ADD COLUMN port INTEGER")
                if (!columnExists(db, "log", "flags")) db.execSQL("ALTER TABLE log ADD COLUMN flags TEXT")
                oldVersion = 3
            }
            if (oldVersion < 4) {
                if (!columnExists(db, "log", "connection")) db.execSQL("ALTER TABLE log ADD COLUMN connection INTEGER")
                oldVersion = 4
            }
            if (oldVersion < 5) {
                if (!columnExists(db, "log", "interactive")) db.execSQL("ALTER TABLE log ADD COLUMN interactive INTEGER")
                oldVersion = 5
            }
            if (oldVersion < 6) {
                if (!columnExists(db, "log", "allowed")) db.execSQL("ALTER TABLE log ADD COLUMN allowed INTEGER")
                oldVersion = 6
            }
            if (oldVersion < 7) {
                db.execSQL("DROP TABLE log")
                createTableLog(db)
                oldVersion = 8
            }
            if (oldVersion < 8) {
                if (!columnExists(db, "log", "data")) db.execSQL("ALTER TABLE log ADD COLUMN data TEXT")
                db.execSQL("DROP INDEX idx_log_source")
                db.execSQL("DROP INDEX idx_log_dest")
                db.execSQL("CREATE INDEX idx_log_source ON log(saddr)")
                db.execSQL("CREATE INDEX idx_log_dest ON log(daddr)")
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_uid ON log(uid)")
                oldVersion = 8
            }
            if (oldVersion < 9) {
                createTableAccess(db)
                oldVersion = 9
            }
            if (oldVersion < 10) {
                db.execSQL("DROP TABLE log")
                db.execSQL("DROP TABLE access")
                createTableLog(db)
                createTableAccess(db)
                oldVersion = 10
            }
            if (oldVersion < 12) {
                db.execSQL("DROP TABLE access")
                createTableAccess(db)
                oldVersion = 12
            }
            if (oldVersion < 13) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_dport ON log(dport)")
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_dname ON log(dname)")
                oldVersion = 13
            }
            if (oldVersion < 14) {
                createTableDns(db)
                oldVersion = 14
            }
            if (oldVersion < 15) {
                db.execSQL("DROP TABLE access")
                createTableAccess(db)
                oldVersion = 15
            }
            if (oldVersion < 16) {
                createTableForward(db)
                oldVersion = 16
            }
            if (oldVersion < 17) {
                if (!columnExists(db, "access", "sent")) db.execSQL("ALTER TABLE access ADD COLUMN sent INTEGER")
                if (!columnExists(db, "access", "received")) db.execSQL("ALTER TABLE access ADD COLUMN received INTEGER")
                oldVersion = 17
            }
            if (oldVersion < 18) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_access_block ON access(block)")
                db.execSQL("DROP INDEX idx_dns")
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS idx_dns ON dns(qname, aname, resource)")
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_dns_resource ON dns(resource)")
                oldVersion = 18
            }
            if (oldVersion < 19) {
                if (!columnExists(db, "access", "connections")) db.execSQL("ALTER TABLE access ADD COLUMN connections INTEGER")
                oldVersion = 19
            }
            if (oldVersion < 20) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_access_daddr ON access(daddr)")
                oldVersion = 20
            }
            if (oldVersion < 21) {
                createTableApp(db)
                oldVersion = 21
            }
            if (oldVersion == DB_VERSION) {
                db.version = oldVersion
                db.setTransactionSuccessful()
                Log.i(TAG, DB_NAME + " upgraded to " + DB_VERSION)
            } else throw IllegalArgumentException(DB_NAME + " upgraded to " + oldVersion + " but required " + DB_VERSION)
        } catch (ex: Throwable) {
            Log.e(TAG, """
     $ex
     ${Log.getStackTraceString(ex)}
     """.trimIndent())
        } finally {
            db.endTransaction()
        }
    }

    // Log
    fun insertLog(packet: Packet, dname: String?, connection: Int, interactive: Boolean) {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                val cv = ContentValues()
                cv.put("time", packet.time)
                cv.put("version", packet.version)
                if (packet.protocol < 0) cv.putNull("protocol") else cv.put("protocol", packet.protocol)
                cv.put("flags", packet.flags)
                cv.put("saddr", packet.saddr)
                if (packet.sport < 0) cv.putNull("sport") else cv.put("sport", packet.sport)
                cv.put("daddr", packet.daddr)
                if (packet.dport < 0) cv.putNull("dport") else cv.put("dport", packet.dport)
                if (dname == null) cv.putNull("dname") else cv.put("dname", dname)
                cv.put("data", packet.data)
                if (packet.uid < 0) cv.putNull("uid") else cv.put("uid", packet.uid)
                cv.put("allowed", if (packet.allowed) 1 else 0)
                cv.put("connection", connection)
                cv.put("interactive", if (interactive) 1 else 0)
                if (db.insert("log", null, cv) == -1L) Log.e(TAG, "Insert log failed")
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyLogChanged()
    }

    fun clearLog(uid: Int) {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                if (uid < 0) db.delete("log", null, arrayOf()) else db.delete("log", "uid = ?", arrayOf(Integer.toString(uid)))
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
            db.execSQL("VACUUM")
        } finally {
            lock.writeLock().unlock()
        }
        notifyLogChanged()
    }

    fun cleanupLog(time: Long) {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                // There an index on time
                val rows = db.delete("log", "time < ?", arrayOf(java.lang.Long.toString(time)))
                Log.i(TAG, "Cleanup log" +
                        " before=" + SimpleDateFormat.getDateTimeInstance().format(Date(time)) +
                        " rows=" + rows)
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
    }

    fun getLog(udp: Boolean, tcp: Boolean, other: Boolean, allowed: Boolean, blocked: Boolean): Cursor {
        lock.readLock().lock()
        return try {
            val db = this.readableDatabase
            // There is an index on time
            // There is no index on protocol/allowed for write performance
            var query = "SELECT ID AS _id, *"
            query += " FROM log"
            query += " WHERE (0 = 1"
            if (udp) query += " OR protocol = 17"
            if (tcp) query += " OR protocol = 6"
            if (other) query += " OR (protocol <> 6 AND protocol <> 17)"
            query += ") AND (0 = 1"
            if (allowed) query += " OR allowed = 1"
            if (blocked) query += " OR allowed = 0"
            query += ")"
            query += " ORDER BY time DESC"
            db.rawQuery(query, arrayOf())
        } finally {
            lock.readLock().unlock()
        }
    }

    fun searchLog(find: String): Cursor {
        lock.readLock().lock()
        return try {
            val db = this.readableDatabase
            // There is an index on daddr, dname, dport and uid
            var query = "SELECT ID AS _id, *"
            query += " FROM log"
            query += " WHERE daddr LIKE ? OR dname LIKE ? OR dport = ? OR uid = ?"
            query += " ORDER BY time DESC"
            db.rawQuery(query, arrayOf("%$find%", "%$find%", find, find))
        } finally {
            lock.readLock().unlock()
        }
    }

    // Access
    fun updateAccess(packet: Packet, dname: String?, block: Int): Boolean {
        val rows: Int
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                val cv = ContentValues()
                cv.put("time", packet.time)
                cv.put("allowed", if (packet.allowed) 1 else 0)
                if (block >= 0) cv.put("block", block)

                // There is a segmented index on uid, version, protocol, daddr and dport
                rows = db.update("access", cv, "uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?", arrayOf(
                        Integer.toString(packet.uid),
                        Integer.toString(packet.version),
                        Integer.toString(packet.protocol),
                        dname ?: packet.daddr,
                        Integer.toString(packet.dport)))
                if (rows == 0) {
                    cv.put("uid", packet.uid)
                    cv.put("version", packet.version)
                    cv.put("protocol", packet.protocol)
                    cv.put("daddr", dname ?: packet.daddr)
                    cv.put("dport", packet.dport)
                    if (block < 0) cv.put("block", block)
                    if (db.insert("access", null, cv) == -1L) Log.e(TAG, "Insert access failed")
                } else if (rows != 1) Log.e(TAG, "Update access failed rows=$rows")
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyAccessChanged()
        return rows == 0
    }

    fun updateUsage(usage: Usage, dname: String?) {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                // There is a segmented index on uid, version, protocol, daddr and dport
                val selection = "uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?"
                val selectionArgs = arrayOf(
                        Integer.toString(usage.Uid),
                        Integer.toString(usage.Version),
                        Integer.toString(usage.Protocol),
                        dname ?: usage.DAddr,
                        Integer.toString(usage.DPort)
                )
                db.query("access", arrayOf("sent", "received", "connections"), selection, selectionArgs, null, null, null).use { cursor ->
                    var sent: Long = 0
                    var received: Long = 0
                    var connections = 0
                    val colSent = cursor.getColumnIndex("sent")
                    val colReceived = cursor.getColumnIndex("received")
                    val colConnections = cursor.getColumnIndex("connections")
                    if (cursor.moveToNext()) {
                        sent = if (cursor.isNull(colSent)) 0 else cursor.getLong(colSent)
                        received = if (cursor.isNull(colReceived)) 0 else cursor.getLong(colReceived)
                        connections = if (cursor.isNull(colConnections)) 0 else cursor.getInt(colConnections)
                    }
                    val cv = ContentValues()
                    cv.put("sent", sent + usage.Sent)
                    cv.put("received", received + usage.Received)
                    cv.put("connections", connections + 1)
                    val rows = db.update("access", cv, selection, selectionArgs)
                    if (rows != 1) Log.e(TAG, "Update usage failed rows=$rows")
                }
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyAccessChanged()
    }

    fun setAccess(id: Long, block: Int) {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                val cv = ContentValues()
                cv.put("block", block)
                cv.put("allowed", -1)
                if (db.update("access", cv, "ID = ?", arrayOf(java.lang.Long.toString(id))) != 1) Log.e(TAG, "Set access failed")
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyAccessChanged()
    }

    fun clearAccess() {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                db.delete("access", null, null)
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyAccessChanged()
    }

    fun clearAccess(uid: Int, keeprules: Boolean) {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                // There is a segmented index on uid
                // There is an index on block
                if (keeprules) db.delete("access", "uid = ? AND block < 0", arrayOf(Integer.toString(uid))) else db.delete("access", "uid = ?", arrayOf(Integer.toString(uid)))
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyAccessChanged()
    }

    fun resetUsage(uid: Int) {
        lock.writeLock().lock()
        try {
            // There is a segmented index on uid
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                val cv = ContentValues()
                cv.putNull("sent")
                cv.putNull("received")
                cv.putNull("connections")
                db.update("access", cv,
                        if (uid < 0) null else "uid = ?",
                        if (uid < 0) null else arrayOf(Integer.toString(uid)))
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyAccessChanged()
    }

    fun getAccess(uid: Int): Cursor {
        lock.readLock().lock()
        return try {
            val db = this.readableDatabase
            // There is a segmented index on uid
            // There is no index on time for write performance
            var query = "SELECT a.ID AS _id, a.*"
            query += ", (SELECT COUNT(DISTINCT d.qname) FROM dns d WHERE d.resource IN (SELECT d1.resource FROM dns d1 WHERE d1.qname = a.daddr)) count"
            query += " FROM access a"
            query += " WHERE a.uid = ?"
            query += " ORDER BY a.time DESC"
            query += " LIMIT 250"
            db.rawQuery(query, arrayOf(Integer.toString(uid)))
        } finally {
            lock.readLock().unlock()
        }
    }

    // There is a segmented index on uid
    // There is an index on block
    val access: Cursor
        get() {
            lock.readLock().lock()
            return try {
                val db = this.readableDatabase
                // There is a segmented index on uid
                // There is an index on block
                db.query("access", null, "block >= 0", null, null, null, "uid")
            } finally {
                lock.readLock().unlock()
            }
        }

    fun getAccessUnset(uid: Int, limit: Int, since: Long): Cursor {
        lock.readLock().lock()
        return try {
            val db = this.readableDatabase
            // There is a segmented index on uid, block and daddr
            // There is no index on allowed and time for write performance
            var query = "SELECT MAX(time) AS time, daddr, allowed"
            query += " FROM access"
            query += " WHERE uid = ?"
            query += " AND block < 0"
            query += " AND time >= ?"
            query += " GROUP BY daddr, allowed"
            query += " ORDER BY time DESC"
            if (limit > 0) query += " LIMIT $limit"
            db.rawQuery(query, arrayOf(Integer.toString(uid), java.lang.Long.toString(since)))
        } finally {
            lock.readLock().unlock()
        }
    }

    fun getHostCount(uid: Int, usecache: Boolean): Long {
        if (usecache) synchronized(mapUidHosts) { if (mapUidHosts.containsKey(uid)) return mapUidHosts[uid]!! }
        lock.readLock().lock()
        return try {
            val db = this.readableDatabase
            // There is a segmented index on uid
            // There is an index on block
            val hosts = db.compileStatement("SELECT COUNT(*) FROM access WHERE block >= 0 AND uid =$uid").simpleQueryForLong()
            synchronized(mapUidHosts) { mapUidHosts.put(uid, hosts) }
            hosts
        } finally {
            lock.readLock().unlock()
        }
    }

    // DNS
    fun insertDns(rr: ResourceRecord): Boolean {
        lock.writeLock().lock()
        return try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                var ttl = rr.TTL
                val min = prefs.getString("ttl", "259200")!!.toInt()
                if (ttl < min) ttl = min
                val cv = ContentValues()
                cv.put("time", rr.Time)
                cv.put("ttl", ttl * 1000L)
                var rows = db.update("dns", cv, "qname = ? AND aname = ? AND resource = ?", arrayOf(rr.QName, rr.AName, rr.Resource))
                if (rows == 0) {
                    cv.put("qname", rr.QName)
                    cv.put("aname", rr.AName)
                    cv.put("resource", rr.Resource)
                    if (db.insert("dns", null, cv) == -1L) Log.e(TAG, "Insert dns failed") else rows = 1
                } else if (rows != 1) Log.e(TAG, "Update dns failed rows=$rows")
                db.setTransactionSuccessful()
                rows > 0
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
    }

    fun cleanupDns() {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                // There is no index on time for write performance
                val now = Date().time
                db.execSQL("DELETE FROM dns WHERE time + ttl < $now")
                Log.i(TAG, "Cleanup DNS")
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
    }

    fun clearDns() {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                db.delete("dns", null, arrayOf())
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
    }

    fun getQName(uid: Int, ip: String): String? {
        lock.readLock().lock()
        return try {
            val db = this.readableDatabase
            // There is a segmented index on resource
            var query = "SELECT d.qname"
            query += " FROM dns AS d"
            query += " WHERE d.resource = '" + ip.replace("'", "''") + "'"
            query += " ORDER BY d.qname"
            query += " LIMIT 1"
            // There is no way to known for sure which domain name an app used, so just pick the first one
            db.compileStatement(query).simpleQueryForString()
        } catch (ignored: SQLiteDoneException) {
            // Not found
            null
        } finally {
            lock.readLock().unlock()
        }
    }

    fun getAlternateQNames(qname: String): Cursor {
        lock.readLock().lock()
        return try {
            val db = this.readableDatabase
            var query = "SELECT DISTINCT d2.qname"
            query += " FROM dns d1"
            query += " JOIN dns d2"
            query += "   ON d2.resource = d1.resource AND d2.id <> d1.id"
            query += " WHERE d1.qname = ?"
            query += " ORDER BY d2.qname"
            db.rawQuery(query, arrayOf(qname))
        } finally {
            lock.readLock().unlock()
        }
    }

    // There is an index on resource
    // There is a segmented index on qname
    val dns: Cursor
        get() {
            lock.readLock().lock()
            return try {
                val db = this.readableDatabase
                // There is an index on resource
                // There is a segmented index on qname
                var query = "SELECT ID AS _id, *"
                query += " FROM dns"
                query += " ORDER BY resource, qname"
                db.rawQuery(query, arrayOf())
            } finally {
                lock.readLock().unlock()
            }
        }

    fun getAccessDns(dname: String?): Cursor {
        val now = Date().time
        lock.readLock().lock()
        return try {
            val db = this.readableDatabase

            // There is a segmented index on dns.qname
            // There is an index on access.daddr and access.block
            var query = "SELECT a.uid, a.version, a.protocol, a.daddr, d.resource, a.dport, a.block, d.time, d.ttl"
            query += " FROM access AS a"
            query += " LEFT JOIN dns AS d"
            query += "   ON d.qname = a.daddr"
            query += " WHERE a.block >= 0"
            query += " AND (d.time IS NULL OR d.time + d.ttl >= $now)"
            if (dname != null) query += " AND a.daddr = ?"
            db.rawQuery(query, dname?.let { arrayOf(it) } ?: arrayOf())
        } finally {
            lock.readLock().unlock()
        }
    }

    // Forward
    fun addForward(protocol: Int, dport: Int, raddr: String?, rport: Int, ruid: Int) {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                val cv = ContentValues()
                cv.put("protocol", protocol)
                cv.put("dport", dport)
                cv.put("raddr", raddr)
                cv.put("rport", rport)
                cv.put("ruid", ruid)
                if (db.insert("forward", null, cv) < 0) Log.e(TAG, "Insert forward failed")
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyForwardChanged()
    }

    fun deleteForward() {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                db.delete("forward", null, null)
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyForwardChanged()
    }

    fun deleteForward(protocol: Int, dport: Int) {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                db.delete("forward", "protocol = ? AND dport = ?", arrayOf(Integer.toString(protocol), Integer.toString(dport)))
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
        notifyForwardChanged()
    }

    val forwarding: Cursor
        get() {
            lock.readLock().lock()
            return try {
                val db = this.readableDatabase
                var query = "SELECT ID AS _id, *"
                query += " FROM forward"
                query += " ORDER BY dport"
                db.rawQuery(query, arrayOf())
            } finally {
                lock.readLock().unlock()
            }
        }

    fun addApp(packageName: String?, label: String?, system: Boolean, internet: Boolean, enabled: Boolean) {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                val cv = ContentValues()
                cv.put("package", packageName)
                if (label == null) cv.putNull("label") else cv.put("label", label)
                cv.put("system", if (system) 1 else 0)
                cv.put("internet", if (internet) 1 else 0)
                cv.put("enabled", if (enabled) 1 else 0)
                if (db.insert("app", null, cv) < 0) Log.e(TAG, "Insert app failed")
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
    }

    fun getApp(packageName: String): Cursor {
        lock.readLock().lock()
        return try {
            val db = this.readableDatabase

            // There is an index on package
            val query = "SELECT * FROM app WHERE package = ?"
            db.rawQuery(query, arrayOf(packageName))
        } finally {
            lock.readLock().unlock()
        }
    }

    fun clearApps() {
        lock.writeLock().lock()
        try {
            val db = this.writableDatabase
            db.beginTransactionNonExclusive()
            try {
                db.delete("app", null, null)
                db.setTransactionSuccessful()
            } finally {
                db.endTransaction()
            }
        } finally {
            lock.writeLock().unlock()
        }
    }

    fun addLogChangedListener(listener: LogChangedListener) {
        logChangedListeners.add(listener)
    }

    fun removeLogChangedListener(listener: LogChangedListener) {
        logChangedListeners.remove(listener)
    }

    fun addAccessChangedListener(listener: AccessChangedListener) {
        accessChangedListeners.add(listener)
    }

    fun removeAccessChangedListener(listener: AccessChangedListener) {
        accessChangedListeners.remove(listener)
    }

    fun addForwardChangedListener(listener: ForwardChangedListener) {
        forwardChangedListeners.add(listener)
    }

    fun removeForwardChangedListener(listener: ForwardChangedListener) {
        forwardChangedListeners.remove(listener)
    }

    private fun notifyLogChanged() {
        val msg = handler!!.obtainMessage()
        msg.what = MSG_LOG
        handler!!.sendMessage(msg)
    }

    private fun notifyAccessChanged() {
        val msg = handler!!.obtainMessage()
        msg.what = MSG_ACCESS
        handler!!.sendMessage(msg)
    }

    private fun notifyForwardChanged() {
        val msg = handler!!.obtainMessage()
        msg.what = MSG_FORWARD
        handler!!.sendMessage(msg)
    }

    interface LogChangedListener {
        fun onChanged()
    }

    interface AccessChangedListener {
        fun onChanged()
    }

    interface ForwardChangedListener {
        fun onChanged()
    }

    init {
        if (!once) {
            once = true
            val dbfile = context.getDatabasePath(DB_NAME)
            if (dbfile.exists()) {
                Log.w(TAG, "Deleting $dbfile")
                dbfile.delete()
            }
            val dbjournal = context.getDatabasePath(DB_NAME + "-journal")
            if (dbjournal.exists()) {
                Log.w(TAG, "Deleting $dbjournal")
                dbjournal.delete()
            }
        }
    }
}