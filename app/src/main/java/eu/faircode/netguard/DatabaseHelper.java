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
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class DatabaseHelper extends SQLiteOpenHelper {
    private static final String TAG = "NetGuard.Database";

    private static final String DB_NAME = "Netguard";
    private static final int DB_VERSION = 13;

    private static boolean once = true;
    private static List<LogChangedListener> logChangedListeners = new ArrayList<>();
    private static List<AccessChangedListener> accessChangedListeners = new ArrayList<>();

    private Context mContext;

    public DatabaseHelper(Context context) {
        super(context, DB_NAME, null, DB_VERSION);
        mContext = context;

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

    private void createTableAccess(SQLiteDatabase db) {
        Log.i(TAG, "Creating access table");
        db.execSQL("CREATE TABLE access (" +
                " ID INTEGER PRIMARY KEY AUTOINCREMENT" +
                ", uid INTEGER NOT NULL" +
                ", daddr TEXT NOT NULL" +
                ", dport INTEGER NULL" +
                ", time INTEGER NOT NULL" +
                ", allowed INTEGER NULL" +
                ", block INTEGER NOT NULL" +
                ");");
        db.execSQL("CREATE UNIQUE INDEX idx_access ON access(uid, daddr, dport)");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        Log.i(TAG, DB_NAME + " upgrading from version " + oldVersion + " to " + newVersion);

        db.beginTransaction();
        try {
            if (oldVersion < 2) {
                db.execSQL("ALTER TABLE log ADD COLUMN version INTEGER NULL");
                db.execSQL("ALTER TABLE log ADD COLUMN protocol INTEGER NULL");
                db.execSQL("ALTER TABLE log ADD COLUMN uid INTEGER NULL");
                oldVersion = 2;
            }
            if (oldVersion < 3) {
                db.execSQL("ALTER TABLE log ADD COLUMN port INTEGER NULL");
                db.execSQL("ALTER TABLE log ADD COLUMN flags TEXT");
                oldVersion = 3;
            }
            if (oldVersion < 4) {
                db.execSQL("ALTER TABLE log ADD COLUMN connection INTEGER NULL");
                oldVersion = 4;
            }
            if (oldVersion < 5) {
                db.execSQL("ALTER TABLE log ADD COLUMN interactive INTEGER NULL");
                oldVersion = 5;
            }
            if (oldVersion < 6) {
                db.execSQL("ALTER TABLE log ADD COLUMN allowed INTEGER NULL");
                oldVersion = 6;
            }
            if (oldVersion < 7) {
                db.execSQL("DROP TABLE log");
                createTableLog(db);
                oldVersion = 9;
            }
            if (oldVersion < 8) {
                db.execSQL("ALTER TABLE log ADD COLUMN data TEXT");
                db.execSQL("DROP INDEX idx_log_source");
                db.execSQL("DROP INDEX idx_log_dest");
                db.execSQL("CREATE INDEX idx_log_source ON log(saddr)");
                db.execSQL("CREATE INDEX idx_log_dest ON log(daddr)");
                db.execSQL("CREATE INDEX idx_log_uid ON log(uid)");
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
                db.execSQL("CREATE INDEX idx_log_dport ON log(dport)");
                db.execSQL("CREATE INDEX idx_log_dname ON log(dname)");
                oldVersion = 13;
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
        synchronized (mContext.getApplicationContext()) {
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

        for (LogChangedListener listener : logChangedListeners)
            try {
                listener.onChanged();
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

        return this;
    }

    public DatabaseHelper clearLog() {
        synchronized (mContext.getApplicationContext()) {
            SQLiteDatabase db = this.getReadableDatabase();
            db.delete("log", null, new String[]{});
            db.execSQL("VACUUM");
        }

        for (LogChangedListener listener : logChangedListeners)
            try {
                listener.onChanged();
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

        return this;
    }

    public Cursor getLog() {
        SQLiteDatabase db = this.getReadableDatabase();
        String query = "SELECT ID AS _id, *";
        query += " FROM log";
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
        synchronized (mContext.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();

            ContentValues cv = new ContentValues();
            cv.put("time", packet.time);
            cv.put("allowed", packet.allowed ? 1 : 0);
            if (block >= 0)
                cv.put("block", block);

            rows = db.update("access", cv, "uid = ? AND daddr = ? AND dport = ?",
                    new String[]{
                            Integer.toString(packet.uid),
                            dname == null ? packet.daddr : dname,
                            Integer.toString(packet.dport)});

            if (rows == 0) {
                cv.put("uid", packet.uid);
                cv.put("daddr", dname == null ? packet.daddr : dname);
                cv.put("dport", packet.dport);
                if (block < 0)
                    cv.put("block", block);

                if (db.insert("access", null, cv) == -1)
                    Log.e(TAG, "Insert access failed");
            } else if (rows != 1)
                Log.e(TAG, "Update access failed");
        }

        for (AccessChangedListener listener : accessChangedListeners)
            try {
                listener.onChanged(packet.uid);
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

        return (rows == 0);
    }

    public DatabaseHelper setAccess(long id, int uid, int block) {
        synchronized (mContext.getApplicationContext()) {
            SQLiteDatabase db = this.getWritableDatabase();

            ContentValues cv = new ContentValues();
            cv.put("block", block);
            cv.put("allowed", block < 0 ? -1 : 1 - block);

            if (db.update("access", cv, "ID = ?", new String[]{Long.toString(id)}) != 1)
                Log.e(TAG, "Set access failed");

            for (AccessChangedListener listener : accessChangedListeners)
                try {
                    listener.onChanged(uid);
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                }
        }

        return this;
    }

    public DatabaseHelper clearAccess(int uid) {
        synchronized (mContext.getApplicationContext()) {
            SQLiteDatabase db = this.getReadableDatabase();
            db.delete("access", "uid = ? AND block < 0", new String[]{Integer.toString(uid)});
        }

        for (AccessChangedListener listener : accessChangedListeners)
            try {
                listener.onChanged(uid);
            } catch (Throwable ex) {
                Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
            }

        return this;
    }

    public Cursor getAccess(int uid) {
        SQLiteDatabase db = this.getReadableDatabase();
        String query = "SELECT ID AS _id, *";
        query += " FROM access WHERE uid = ?";
        query += " ORDER BY time DESC";
        return db.rawQuery(query, new String[]{Integer.toString(uid)});
    }

    public Cursor getAccess() {
        SQLiteDatabase db = this.getReadableDatabase();
        return db.query("access", new String[]{"uid", "daddr", "dport", "time", "block"}, "block >= 0", null, null, null, "uid");
    }

    public Cursor getAccessUnset(int uid) {
        SQLiteDatabase db = this.getReadableDatabase();
        return db.query("access", new String[]{"daddr", "dport", "time", "allowed"},
                "uid = ? AND block < 0", new String[]{Integer.toString(uid)},
                null, null, "time DESC");
    }

    public long getRuleCount(int uid) {
        SQLiteDatabase db = this.getReadableDatabase();
        return db.compileStatement("SELECT COUNT(*) FROM access WHERE block >=0 AND uid =" + uid).simpleQueryForLong();
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

    public interface LogChangedListener {
        void onChanged();
    }

    public interface AccessChangedListener {
        void onChanged(int uid);
    }
}
