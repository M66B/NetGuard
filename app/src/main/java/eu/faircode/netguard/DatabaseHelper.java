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

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDoneException;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.preference.PreferenceManager;
import android.util.Log;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class DatabaseHelper extends SQLiteOpenHelper {
    private static final String TAG = "NetGuard.Database";

    private static final String DB_NAME = "Netguard";
    private static final int DB_VERSION = 21;

    private static boolean once = true;
    private static List<LogChangedListener> logChangedListeners = new ArrayList<>();
    private static List<AccessChangedListener> accessChangedListeners = new ArrayList<>();
    private static List<ForwardChangedListener> forwardChangedListeners = new ArrayList<>();

    private static HandlerThread hthread = null;
    private static Handler handler = null;

    private static final Map<Integer, Long> mapUidHosts = new HashMap<>();

    private final static int MSG_LOG = 1;
    private final static int MSG_ACCESS = 2;
    private final static int MSG_FORWARD = 3;

    private SharedPreferences prefs;
    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    static {
        hthread = new HandlerThread("DatabaseHelper");
        hthread.start();
        handler = new Handler(hthread.getLooper()) {
            @Override
            public void handleMessage(Message msg) {
                handleChangedNotification(msg);
            }
        };
    }

    private static DatabaseHelper dh = null;

    public static DatabaseHelper getInstance(Context context) {
        if (dh == null)
            dh = new DatabaseHelper(context.getApplicationContext());
        return dh;
    }

    public static void clearCache() {
        synchronized (mapUidHosts) {
            mapUidHosts.clear();
        }
    }

    @Override
    public void close() {
        Log.w(TAG, "Database is being closed");
    }

    private DatabaseHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
        prefs = PreferenceManager.getDefaultSharedPreferences(context);

        if (!once) {
            once = true;

            File dbfile = context.getDatabasePath(DB_NAME);
            if (dbfile.exists()) {
                Log.w(TAG, "Deleting " + dbfile);
                dbfile.delete();
            }

            File dbjournal = context.getDatabasePath(DB_NAME + "-journal");
            if (dbjournal.exists()) {
                Log.w(TAG, "Deleting " + dbjournal);
                dbjournal.delete();
            }
        }
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        Log.i(TAG, "Creating database " + DB_NAME + " version " + DB_VERSION);
        createTableLog(db);
        createTableAccess(db);
        createTableDns(db);
        createTableForward(db);
        createTableApp(db);
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        db.enableWriteAheadLogging();
        super.onConfigure(db);
    }

    private void createTableLog(SQLiteDatabase db) {
        Log.i(TAG, "Creating log table");
        db.execSQL("CREATE TABLE log (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", time INTEGER NOT NULL" +
                ", version INTEGER NULL" +
                ", protocol INTEGER NULL" +
                ", flags TEXT" +
                ", saddr TEXT" +
                ", sport INTEGER NULL" +
                ", daddr TEXT" +
                ", dport INTEGER NULL" +
                ", dname TEXT NULL" +
                ", uid INTEGER NULL" +
                ", data TEXT" +
                ", allowed INTEGER NULL" +
                ", connection INTEGER NULL" +
                ", interactive INTEGER NULL" +
                ");");
        db.execSQL("CREATE INDEX idx_log_time ON log(time)");
        db.execSQL("CREATE INDEX idx_log_dest ON log(daddr)");
        db.execSQL("CREATE INDEX idx_log_dname ON log(dname)");
        db.execSQL("CREATE INDEX idx_log_dport ON log(dport)");
        db.execSQL("CREATE INDEX idx_log_uid ON log(uid)");
    }

    private void createTableAccess(SQLiteDatabase db) {
        Log.i(TAG, "Creating access table");
        db.execSQL("CREATE TABLE access (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", uid INTEGER NOT NULL" +
                ", version INTEGER NOT NULL" +
                ", protocol INTEGER NOT NULL" +
                ", daddr TEXT NOT NULL" +
                ", dport INTEGER NOT NULL" +
                ", time INTEGER NOT NULL" +
                ", allowed INTEGER NULL" +
                ", block INTEGER NOT NULL" +
                ", sent INTEGER NULL" +
                ", received INTEGER NULL" +
                ", connections INTEGER NULL" +
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_access ON access(uid, version, protocol, daddr, dport)");
        db.execSQL("CREATE INDEX idx_access_daddr ON access(daddr)");
        db.execSQL("CREATE INDEX idx_access_block ON access(block)");
    }

    private void createTableDns(SQLiteDatabase db) {
        Log.i(TAG, "Creating dns table");
        db.execSQL("CREATE TABLE dns (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", time INTEGER NOT NULL" +
                ", qname TEXT NOT NULL" +
                ", aname TEXT NOT NULL" +
                ", resource TEXT NOT NULL" +
                ", ttl INTEGER NULL" +
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_dns ON dns(qname, aname, resource)");
        db.execSQL("CREATE INDEX idx_dns_resource ON dns(resource)");
    }

    private void createTableForward(SQLiteDatabase db) {
        Log.i(TAG, "Creating forward table");
        db.execSQL("CREATE TABLE forward (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", protocol INTEGER NOT NULL" +
                ", dport INTEGER NOT NULL" +
                ", raddr TEXT NOT NULL" +
                ", rport INTEGER NOT NULL" +
                ", ruid INTEGER NOT NULL" +
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_forward ON forward(protocol, dport)");
    }

    private void createTableApp(SQLiteDatabase db) {
        Log.i(TAG, "Creating app table");
        db.execSQL("CREATE TABLE app (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", package TEXT" +
                ", label TEXT" +
                ", system INTEGER  NOT NULL" +
                ", internet INTEGER NOT NULL" +
                ", enabled INTEGER NOT NULL" +
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_package ON app(package)");
    }

    private boolean columnExists(SQLiteDatabase db, String table, String column) {
        Cursor cursor = null;
        try {
            cursor = db.rawQuery("SELECT * FROM " + table + " LIMIT 0", null);
            return (cursor.getColumnIndex(column) >= 0);
        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            return false;
        } finally {
            if (cursor != null)
                cursor.close();
        }
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.i(TAG, DB_NAME + " upgrading from version " + oldVersion + " to " + newVersion);

        db.beginTransaction();
        try {
            if (oldVersion < 2) {
                if (!columnExists(db, "log", "version"))
                    db.execSQL("ALTER TABLE log ADD COLUMN version INTEGER NULL");
                if (!columnExists(db, "log", "protocol"))
                    db.execSQL("ALTER TABLE log ADD COLUMN protocol INTEGER NULL");
                if (!columnExists(db, "log", "uid"))
                    db.execSQL("ALTER TABLE log ADD COLUMN uid INTEGER NULL");
                oldVersion = 2;
            }
            if (oldVersion < 3) {
                if (!columnExists(db, "log", "port"))
                    db.execSQL("ALTER TABLE log ADD COLUMN port INTEGER NULL");
                if (!columnExists(db, "log", "flags"))
                    db.execSQL("ALTER TABLE log ADD COLUMN flags TEXT");
                oldVersion = 3;
            }
            if (oldVersion < 4) {
                if (!columnExists(db, "log", "connection"))
                    db.execSQL("ALTER TABLE log ADD COLUMN connection INTEGER NULL");
                oldVersion = 4;
            }
            if (oldVersion < 5) {
                if (!columnExists(db, "log", "interactive"))
                    db.execSQL("ALTER TABLE log ADD COLUMN interactive INTEGER NULL");
                oldVersion = 5;
            }
            if (oldVersion < 6) {
                if (!columnExists(db, "log", "allowed"))
                    db.execSQL("ALTER TABLE log ADD COLUMN allowed INTEGER NULL");
                oldVersion = 6;
            }
            if (oldVersion < 7) {
                db.execSQL("DROP TABLE log");
                createTableLog(db);
                oldVersion = 8;
            }
            if (oldVersion < 8) {
                if (!columnExists(db, "log", "data"))
                    db.execSQL("ALTER TABLE log ADD COLUMN data TEXT");
                db.execSQL("DROP INDEX idx_log_source");
                db.execSQL("DROP INDEX idx_log_dest");
                db.execSQL("CREATE INDEX idx_log_source ON log(saddr)");
                db.execSQL("CREATE INDEX idx_log_dest ON log(daddr)");
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_uid ON log(uid)");
                oldVersion = 8;
            }
            if (oldVersion < 9) {
                createTableAccess(db);
                oldVersion = 9;
            }
            if (oldVersion < 10) {
                db.execSQL("DROP TABLE log");
                db.execSQL("DROP TABLE access");
                createTableLog(db);
                createTableAccess(db);
                oldVersion = 10;
            }
            if (oldVersion < 12) {
                db.execSQL("DROP TABLE access");
                createTableAccess(db);
                oldVersion = 12;
            }
            if (oldVersion < 13) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_dport ON log(dport)");
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_log_dname ON log(dname)");
                oldVersion = 13;
            }
            if (oldVersion < 14) {
                createTableDns(db);
                oldVersion = 14;
            }
            if (oldVersion < 15) {
                db.execSQL("DROP TABLE access");
                createTableAccess(db);
                oldVersion = 15;
            }
            if (oldVersion < 16) {
                createTableForward(db);
                oldVersion = 16;
            }
            if (oldVersion < 17) {
                if (!columnExists(db, "access", "sent"))
                    db.execSQL("ALTER TABLE access ADD COLUMN sent INTEGER NULL");
                if (!columnExists(db, "access", "received"))
                    db.execSQL("ALTER TABLE access ADD COLUMN received INTEGER NULL");
                oldVersion = 17;
            }
            if (oldVersion < 18) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_access_block ON access(block)");
                db.execSQL("DROP INDEX idx_dns");
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS idx_dns ON dns(qname, aname, resource)");
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_dns_resource ON dns(resource)");
                oldVersion = 18;
            }
            if (oldVersion < 19) {
                if (!columnExists(db, "access", "connections"))
                    db.execSQL("ALTER TABLE access ADD COLUMN connections INTEGER NULL");
                oldVersion = 19;
            }
            if (oldVersion < 20) {
                db.execSQL("CREATE INDEX IF NOT EXISTS idx_access_daddr ON access(daddr)");
                oldVersion = 20;
            }
            if (oldVersion < 21) {
                createTableApp(db);
                oldVersion = 21;
            }

            if (oldVersion == DB_VERSION) {
                db.setVersion(oldVersion);
                db.setTransactionSuccessful();
                Log.i(TAG, DB_NAME + " upgraded to " + DB_VERSION);
            } else
                throw new IllegalArgumentException(DB_NAME + " upgraded to " + oldVersion + " but required " + DB_VERSION);

        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        } finally {
            db.endTransaction();
        }
    }

    // Log

    public void insertLog(Packet packet, String dname, int connection, boolean interactive) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.put("time", packet.time);
                cv.put("version", packet.version);

                if (packet.protocol < 0)
                    cv.putNull("protocol");
                else
                    cv.put("protocol", packet.protocol);

                cv.put("flags", packet.flags);

                cv.put("saddr", packet.saddr);
                if (packet.sport < 0)
                    cv.putNull("sport");
                else
                    cv.put("sport", packet.sport);

                cv.put("daddr", packet.daddr);
                if (packet.dport < 0)
                    cv.putNull("dport");
                else
                    cv.put("dport", packet.dport);

                if (dname == null)
                    cv.putNull("dname");
                else
                    cv.put("dname", dname);

                cv.put("data", packet.data);

                if (packet.uid < 0)
                    cv.putNull("uid");
                else
                    cv.put("uid", packet.uid);

                cv.put("allowed", packet.allowed ? 1 : 0);

                cv.put("connection", connection);
                cv.put("interactive", interactive ? 1 : 0);

                if (db.insert("log", null, cv) == -1)
                    Log.e(TAG, "Insert log failed");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyLogChanged();
    }

    public void clearLog(int uid) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                if (uid < 0)
                    db.delete("log", null, new String[]{});
                else
                    db.delete("log", "uid = ?", new String[]{Integer.toString(uid)});

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }

            db.execSQL("VACUUM");
        } finally {
            lock.writeLock().unlock();
        }

        notifyLogChanged();
    }

    public void cleanupLog(long time) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                // There an index on time
                int rows = db.delete("log", "time < ?", new String[]{Long.toString(time)});
                Log.i(TAG, "Cleanup log" +
                        " before=" + SimpleDateFormat.getDateTimeInstance().format(new Date(time)) +
                        " rows=" + rows);

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Cursor getLog(boolean udp, boolean tcp, boolean other, boolean allowed, boolean blocked) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is an index on time
            // There is no index on protocol/allowed for write performance
            String query = "SELECT ID AS _id, *";
            query += " FROM log";
            query += " WHERE (0 = 1";
            if (udp)
                query += " OR protocol = 17";
            if (tcp)
                query += " OR protocol = 6";
            if (other)
                query += " OR (protocol <> 6 AND protocol <> 17)";
            query += ") AND (0 = 1";
            if (allowed)
                query += " OR allowed = 1";
            if (blocked)
                query += " OR allowed = 0";
            query += ")";
            query += " ORDER BY time DESC";
            return db.rawQuery(query, new String[]{});
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor searchLog(String find) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is an index on daddr, dname, dport and uid
            String query = "SELECT ID AS _id, *";
            query += " FROM log";
            query += " WHERE daddr LIKE ? OR dname LIKE ? OR dport = ? OR uid = ?";
            query += " ORDER BY time DESC";
            return db.rawQuery(query, new String[]{"%" + find + "%", "%" + find + "%", find, find});
        } finally {
            lock.readLock().unlock();
        }
    }

    // Access

    public boolean updateAccess(Packet packet, String dname, int block) {
        int rows;

        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.put("time", packet.time);
                cv.put("allowed", packet.allowed ? 1 : 0);
                if (block >= 0)
                    cv.put("block", block);

                // There is a segmented index on uid, version, protocol, daddr and dport
                rows = db.update("access", cv, "uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?",
                        new String[]{
                                Integer.toString(packet.uid),
                                Integer.toString(packet.version),
                                Integer.toString(packet.protocol),
                                dname == null ? packet.daddr : dname,
                                Integer.toString(packet.dport)});

                if (rows == 0) {
                    cv.put("uid", packet.uid);
                    cv.put("version", packet.version);
                    cv.put("protocol", packet.protocol);
                    cv.put("daddr", dname == null ? packet.daddr : dname);
                    cv.put("dport", packet.dport);
                    if (block < 0)
                        cv.put("block", block);

                    if (db.insert("access", null, cv) == -1)
                        Log.e(TAG, "Insert access failed");
                } else if (rows != 1)
                    Log.e(TAG, "Update access failed rows=" + rows);

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
        return (rows == 0);
    }

    public void updateUsage(Usage usage, String dname) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                // There is a segmented index on uid, version, protocol, daddr and dport
                String selection = "uid = ? AND version = ? AND protocol = ? AND daddr = ? AND dport = ?";
                String[] selectionArgs = new String[]{
                        Integer.toString(usage.Uid),
                        Integer.toString(usage.Version),
                        Integer.toString(usage.Protocol),
                        dname == null ? usage.DAddr : dname,
                        Integer.toString(usage.DPort)
                };

                Cursor cursor = db.query("access", new String[]{"sent", "received", "connections"}, selection, selectionArgs, null, null, null);
                long sent = 0;
                long received = 0;
                int connections = 0;
                int colSent = cursor.getColumnIndex("sent");
                int colReceived = cursor.getColumnIndex("received");
                int colConnections = cursor.getColumnIndex("connections");
                if (cursor.moveToNext()) {
                    sent = cursor.isNull(colSent) ? 0 : cursor.getLong(colSent);
                    received = cursor.isNull(colReceived) ? 0 : cursor.getLong(colReceived);
                    connections = cursor.isNull(colConnections) ? 0 : cursor.getInt(colConnections);
                }
                cursor.close();

                ContentValues cv = new ContentValues();
                cv.put("sent", sent + usage.Sent);
                cv.put("received", received + usage.Received);
                cv.put("connections", connections + 1);

                int rows = db.update("access", cv, selection, selectionArgs);
                if (rows != 1)
                    Log.e(TAG, "Update usage failed rows=" + rows);

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public void setAccess(long id, int block) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.put("block", block);
                cv.put("allowed", -1);

                if (db.update("access", cv, "ID = ?", new String[]{Long.toString(id)}) != 1)
                    Log.e(TAG, "Set access failed");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public void clearAccess() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("access", null, null);

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public void clearAccess(int uid, boolean keeprules) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                // There is a segmented index on uid
                // There is an index on block
                if (keeprules)
                    db.delete("access", "uid = ? AND block < 0", new String[]{Integer.toString(uid)});
                else
                    db.delete("access", "uid = ?", new String[]{Integer.toString(uid)});

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public void resetUsage(int uid) {
        lock.writeLock().lock();
        try {
            // There is a segmented index on uid
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.putNull("sent");
                cv.putNull("received");
                cv.putNull("connections");
                db.update("access", cv,
                        (uid < 0 ? null : "uid = ?"),
                        (uid < 0 ? null : new String[]{Integer.toString(uid)}));

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyAccessChanged();
    }

    public Cursor getAccess(int uid) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is no index on time for write performance
            String query = "SELECT a.ID AS _id, a.*";
            query += ", (SELECT COUNT(DISTINCT d.qname) FROM dns d WHERE d.resource IN (SELECT d1.resource FROM dns d1 WHERE d1.qname = a.daddr)) count";
            query += " FROM access a";
            query += " WHERE a.uid = ?";
            query += " ORDER BY a.time DESC";
            query += " LIMIT 50";
            return db.rawQuery(query, new String[]{Integer.toString(uid)});
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getAccess() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is an index on block
            return db.query("access", null, "block >= 0", null, null, null, "uid");
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getAccessUnset(int uid, int limit, long since) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid, block and daddr
            // There is no index on allowed and time for write performance
            String query = "SELECT MAX(time) AS time, daddr, allowed";
            query += " FROM access";
            query += " WHERE uid = ?";
            query += " AND block < 0";
            query += " AND time >= ?";
            query += " GROUP BY daddr, allowed";
            query += " ORDER BY time DESC";
            if (limit > 0)
                query += " LIMIT " + limit;
            return db.rawQuery(query, new String[]{Integer.toString(uid), Long.toString(since)});
        } finally {
            lock.readLock().unlock();
        }
    }

    public long getHostCount(int uid, boolean usecache) {
        if (usecache)
            synchronized (mapUidHosts) {
                if (mapUidHosts.containsKey(uid))
                    return mapUidHosts.get(uid);
            }

        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on uid
            // There is an index on block
            long hosts = db.compileStatement("SELECT COUNT(*) FROM access WHERE block >= 0 AND uid =" + uid).simpleQueryForLong();
            synchronized (mapUidHosts) {
                mapUidHosts.put(uid, hosts);
            }
            return hosts;
        } finally {
            lock.readLock().unlock();
        }
    }

    // DNS

    public boolean insertDns(ResourceRecord rr) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                int ttl = rr.TTL;

                int min = Integer.parseInt(prefs.getString("ttl", "259200"));
                if (ttl < min)
                    ttl = min;

                ContentValues cv = new ContentValues();
                cv.put("time", rr.Time);
                cv.put("ttl", ttl * 1000L);

                int rows = db.update("dns", cv, "qname = ? AND aname = ? AND resource = ?",
                        new String[]{rr.QName, rr.AName, rr.Resource});

                if (rows == 0) {
                    cv.put("qname", rr.QName);
                    cv.put("aname", rr.AName);
                    cv.put("resource", rr.Resource);

                    if (db.insert("dns", null, cv) == -1)
                        Log.e(TAG, "Insert dns failed");
                } else if (rows != 1)
                    Log.e(TAG, "Update dns failed rows=" + rows);

                db.setTransactionSuccessful();

                return (rows == 0);
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void cleanupDns() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                // There is no index on time for write performance
                long now = new Date().getTime();
                db.execSQL("DELETE FROM dns WHERE time + ttl < " + now);
                Log.i(TAG, "Cleanup DNS");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void clearDns() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("dns", null, new String[]{});

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public String getQName(int uid, String ip) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is a segmented index on resource
            // There is an index on access.daddr
            String query = "SELECT d.qname";
            query += " FROM dns AS d";
            query += " LEFT JOIN access AS a";
            query += "   ON a.daddr = d.qname AND a.uid = " + uid;
            query += " WHERE d.resource = '" + ip.replace("'", "''") + "'";
            query += " ORDER BY CASE a.daddr WHEN NULL THEN 1 ELSE 0 END, d.qname";
            query += " LIMIT 1";
            return db.compileStatement(query).simpleQueryForString();
        } catch (SQLiteDoneException ignored) {
            // Not found
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getAlternateQNames(String qname) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            String query = "SELECT DISTINCT d2.qname";
            query += " FROM dns d1";
            query += " JOIN dns d2";
            query += "   ON d2.resource = d1.resource AND d2.id <> d1.id";
            query += " WHERE d1.qname = ?";
            query += " ORDER BY d2.qname";
            return db.rawQuery(query, new String[]{qname});
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getDns() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            // There is an index on resource
            // There is a segmented index on qname
            String query = "SELECT ID AS _id, *";
            query += " FROM dns";
            query += " ORDER BY resource, qname";
            return db.rawQuery(query, new String[]{});
        } finally {
            lock.readLock().unlock();
        }
    }

    public Cursor getAccessDns(String dname) {
        long now = new Date().getTime();
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();

            // There is a segmented index on dns.qname
            // There is an index on access.daddr and access.block
            String query = "SELECT a.uid, a.version, a.protocol, a.daddr, d.resource, a.dport, a.block, d.time, d.ttl";
            query += " FROM access AS a";
            query += " LEFT JOIN dns AS d";
            query += "   ON d.qname = a.daddr";
            query += " WHERE a.block >= 0";
            query += " AND d.time + d.ttl >= " + now;
            if (dname != null)
                query += " AND a.daddr = ?";

            return db.rawQuery(query, dname == null ? new String[]{} : new String[]{dname});
        } finally {
            lock.readLock().unlock();
        }
    }

    // Forward

    public void addForward(int protocol, int dport, String raddr, int rport, int ruid) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.put("protocol", protocol);
                cv.put("dport", dport);
                cv.put("raddr", raddr);
                cv.put("rport", rport);
                cv.put("ruid", ruid);

                if (db.insert("forward", null, cv) < 0)
                    Log.e(TAG, "Insert forward failed");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyForwardChanged();
    }

    public void deleteForward() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("forward", null, null);

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyForwardChanged();
    }

    public void deleteForward(int protocol, int dport) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("forward", "protocol = ? AND dport = ?",
                        new String[]{Integer.toString(protocol), Integer.toString(dport)});

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }

        notifyForwardChanged();
    }

    public Cursor getForwarding() {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();
            String query = "SELECT ID AS _id, *";
            query += " FROM forward";
            query += " ORDER BY dport";
            return db.rawQuery(query, new String[]{});
        } finally {
            lock.readLock().unlock();
        }
    }

    public void addApp(String packageName, String label, boolean system, boolean internet, boolean enabled) {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                ContentValues cv = new ContentValues();
                cv.put("package", packageName);
                if (label == null)
                    cv.putNull("label");
                else
                    cv.put("label", label);
                cv.put("system", system ? 1 : 0);
                cv.put("internet", internet ? 1 : 0);
                cv.put("enabled", enabled ? 1 : 0);

                if (db.insert("app", null, cv) < 0)
                    Log.e(TAG, "Insert app failed");

                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Cursor getApp(String packageName) {
        lock.readLock().lock();
        try {
            SQLiteDatabase db = this.getReadableDatabase();

            // There is an index on package
            String query = "SELECT * FROM app WHERE package = ?";

            return db.rawQuery(query, new String[]{packageName});
        } finally {
            lock.readLock().unlock();
        }
    }

    public void clearApps() {
        lock.writeLock().lock();
        try {
            SQLiteDatabase db = this.getWritableDatabase();
            db.beginTransactionNonExclusive();
            try {
                db.delete("app", null, null);
                db.setTransactionSuccessful();
            } finally {
                db.endTransaction();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void addLogChangedListener(LogChangedListener listener) {
        logChangedListeners.add(listener);
    }

    public void removeLogChangedListener(LogChangedListener listener) {
        logChangedListeners.remove(listener);
    }

    public void addAccessChangedListener(AccessChangedListener listener) {
        accessChangedListeners.add(listener);
    }

    public void removeAccessChangedListener(AccessChangedListener listener) {
        accessChangedListeners.remove(listener);
    }

    public void addForwardChangedListener(ForwardChangedListener listener) {
        forwardChangedListeners.add(listener);
    }

    public void removeForwardChangedListener(ForwardChangedListener listener) {
        forwardChangedListeners.remove(listener);
    }

    private void notifyLogChanged() {
        Message msg = handler.obtainMessage();
        msg.what = MSG_LOG;
        handler.sendMessage(msg);
    }

    private void notifyAccessChanged() {
        Message msg = handler.obtainMessage();
        msg.what = MSG_ACCESS;
        handler.sendMessage(msg);
    }

    private void notifyForwardChanged() {
        Message msg = handler.obtainMessage();
        msg.what = MSG_FORWARD;
        handler.sendMessage(msg);
    }

    private static void handleChangedNotification(Message msg) {
        // Batch notifications
        try {
            Thread.sleep(1000);
            if (handler.hasMessages(msg.what))
                handler.removeMessages(msg.what);
        } catch (InterruptedException ignored) {
        }

        // Notify listeners
        if (msg.what == MSG_LOG) {
            for (LogChangedListener listener : logChangedListeners)
                try {
                    listener.onChanged();
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

        } else if (msg.what == MSG_ACCESS) {
            for (AccessChangedListener listener : accessChangedListeners)
                try {
                    listener.onChanged();
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }

        } else if (msg.what == MSG_FORWARD) {
            for (ForwardChangedListener listener : forwardChangedListeners)
                try {
                    listener.onChanged();
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
        }
    }

    public interface LogChangedListener {
        void onChanged();
    }

    public interface AccessChangedListener {
        void onChanged();
    }

    public interface ForwardChangedListener {
        void onChanged();
    }
}
