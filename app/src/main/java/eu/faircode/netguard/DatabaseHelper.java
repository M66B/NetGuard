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

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDoneException;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.util.Log;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class DatabaseHelper extends SQLiteOpenHelper {
    private static final String TAG = "NetGuard.Database";

    private static final String DB_NAME = "Netguard";
    private static final int DB_VERSION = 16;

    private static boolean once = true;
    private static List<LogChangedListener> logChangedListeners = new ArrayList<>();
    private static List<AccessChangedListener> accessChangedListeners = new ArrayList<>();

    private Context context;
    private static HandlerThread hthread = null;
    private static Handler handler = null;

    private final static int MSG_LOG = 1;
    private final static int MSG_ACCESS = 2;

    public DatabaseHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
        this.context = context;

        if (hthread == null) {
            hthread = new HandlerThread(getClass().getName());
            hthread.start();
            handler = new Handler(hthread.getLooper()) {
                @Override
                public void handleMessage(Message msg) {
                    handleChangedNotification(msg);
                }
            };
        }

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
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        //db.enableWriteAheadLogging();
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
        db.execSQL("CREATE INDEX idx_log_dport ON log(dport)");
        db.execSQL("CREATE INDEX idx_log_dname ON log(dname)");
        db.execSQL("CREATE INDEX idx_log_uid ON log(uid)");
    }

    // TODO add version, protocol
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
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_access ON access(uid, version, protocol, daddr, dport)");
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
        db.execSQL("CREATE INDEX idx_dns ON dns(qname, aname, resource)");
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

            if (oldVersion == DB_VERSION) {
                db.setVersion(oldVersion);
                db.setTransactionSuccessful();
                Log.e(TAG, DB_NAME + " upgraded to " + DB_VERSION);
            } else
                throw new IllegalArgumentException(DB_NAME + " upgraded to " + oldVersion + " but required " + DB_VERSION);

        } catch (Throwable ex) {
            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
        } finally {
            db.endTransaction();
        }
    }

    // Log

    public DatabaseHelper insertLog(Packet packet, String dname, int connection, boolean interactive) {
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();

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
        }

        notifyLogChanged();
        return this;
    }

    public DatabaseHelper clearLog() {
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getReadableDatabase();
            db.delete("log", null, new String[]{});
            db.execSQL("VACUUM");
        }

        notifyLogChanged();
        return this;
    }

    public Cursor getLog(boolean udp, boolean tcp, boolean other, boolean allowed, boolean blocked) {
        // There is no index on protocol/allowed for write performance
        SQLiteDatabase db = this.getReadableDatabase();
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
    }

    public Cursor searchLog(String find) {
        SQLiteDatabase db = this.getReadableDatabase();
        String query = "SELECT ID AS _id, *";
        query += " FROM log";
        query += " WHERE daddr LIKE ? OR dname LIKE ? OR dport = ? OR uid LIKE ?";
        query += " ORDER BY time DESC";
        return db.rawQuery(query, new String[]{"%" + find + "%", "%" + find + "%", find, "%" + find + "%"});
    }

    // Access

    public boolean updateAccess(Packet packet, String dname, int block) {
        int rows;
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();

            ContentValues cv = new ContentValues();
            cv.put("time", packet.time);
            cv.put("allowed", packet.allowed ? 1 : 0);
            if (block >= 0)
                cv.put("block", block);

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
        }

        notifyAccessChanged();
        return (rows == 0);
    }

    public DatabaseHelper setAccess(long id, int block) {
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();

            ContentValues cv = new ContentValues();
            cv.put("block", block);
            cv.put("allowed", -1);

            if (db.update("access", cv, "ID = ?", new String[]{Long.toString(id)}) != 1)
                Log.e(TAG, "Set access failed");
        }

        notifyAccessChanged();
        return this;
    }

    public DatabaseHelper clearAccess() {
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getReadableDatabase();
            db.delete("access", null, null);
        }

        notifyAccessChanged();
        return this;
    }

    public DatabaseHelper clearAccess(int uid) {
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getReadableDatabase();
            db.delete("access", "uid = ? AND block < 0", new String[]{Integer.toString(uid)});
        }

        notifyAccessChanged();
        return this;
    }

    public Cursor getAccess(int uid) {
        SQLiteDatabase db = this.getReadableDatabase();
        String query = "SELECT ID AS _id, *";
        query += " FROM access WHERE uid = ?";
        query += " ORDER BY time DESC";
        query += " LIMIT 50";
        return db.rawQuery(query, new String[]{Integer.toString(uid)});
    }

    public Cursor getAccess() {
        SQLiteDatabase db = this.getReadableDatabase();
        return db.query("access", null, "block >= 0", null, null, null, "uid");
    }

    public Cursor getAccessUnset(int uid) {
        SQLiteDatabase db = this.getReadableDatabase();
        String query = "SELECT MAX(time) AS time, daddr, allowed";
        query += " FROM access";
        query += " WHERE uid = ?";
        query += " AND block < 0";
        query += " GROUP BY daddr, allowed";
        query += " ORDER BY time DESC";
        return db.rawQuery(query, new String[]{Integer.toString(uid)});
    }

    public long getRuleCount(int uid) {
        SQLiteDatabase db = this.getReadableDatabase();
        return db.compileStatement("SELECT COUNT(*) FROM access WHERE block >=0 AND uid =" + uid).simpleQueryForLong();
    }

    // DNS

    public DatabaseHelper insertDns(ResourceRecord rr) {
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();

            ContentValues cv = new ContentValues();
            cv.put("time", rr.Time);
            cv.put("ttl", rr.TTL);

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
        }

        return this;
    }

    public DatabaseHelper cleanupDns(long time) {
        // There is no index on time for write performance
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();
            int rows = db.delete("dns", "time < ?", new String[]{Long.toString(time)});
            Log.i(TAG, "Cleanup DNS" +
                    " before=" + SimpleDateFormat.getDateTimeInstance().format(new Date(time)) +
                    " rows=" + rows);
        }
        return this;
    }

    public String getQName(String ip) {
        SQLiteDatabase db = this.getReadableDatabase();
        try {
            return db.compileStatement(
                    "SELECT qname FROM dns WHERE resource = '" + ip.replace("'", "''") + "'")
                    .simpleQueryForString();
        } catch (SQLiteDoneException ignored) {
            // Not found
            return null;
        }
    }

    public Cursor getDns() {
        SQLiteDatabase db = this.getReadableDatabase();

        String query = "SELECT a.uid, a.version, a.protocol, a.daddr, d.resource, a.dport, a.block";
        query += " FROM access AS a";
        query += " JOIN dns AS d";
        query += "   ON d.qname = a.daddr";
        query += " WHERE a.block >= 0";

        return db.rawQuery(query, new String[]{});
    }

    // Forward

    public DatabaseHelper addForward(int protocol, int dport, String raddr, int rport, int ruid) {
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();

            ContentValues cv = new ContentValues();
            cv.put("protocol", protocol);
            cv.put("dport", dport);
            cv.put("raddr", raddr);
            cv.put("rport", rport);
            cv.put("ruid", ruid);

            if (db.insert("forward", null, cv) < 0)
                Log.e(TAG, "Insert forward failed");
        }
        return this;
    }

    public DatabaseHelper deleteForward(int protocol, int dport) {
        synchronized (context.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();
            db.delete("forward", "protocol = ? AND dport = ?",
                    new String[]{Integer.toString(protocol), Integer.toString(dport)});
        }
        return this;
    }

    public Cursor getForwarding() {
        SQLiteDatabase db = this.getReadableDatabase();
        String query = "SELECT ID AS _id, *";
        query += " FROM forward";
        query += " ORDER BY dport";
        return db.rawQuery(query, new String[]{});
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
        }
    }

    public interface LogChangedListener {
        void onChanged();
    }

    public interface AccessChangedListener {
        void onChanged();
    }
}
