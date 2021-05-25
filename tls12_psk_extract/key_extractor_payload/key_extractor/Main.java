import java.lang.ClassLoader;

import android.app.Application;

import android.database.sqlite.SQLiteDatabase;


public class Main
{
    private static final String AXOLOTL_DATABASE_PATH = "/data/data/com.whatsapp/databases/axolotl.db";

    private static void extractAllKeys(SQLiteDatabase database)
    {
        Logger.log(String.format("Axolotl database version is %d", database.getVersion()));
        KeyExtractor keyExtractor = new KeyExtractor(database);
        keyExtractor.extractNoiseKeyPair();
        keyExtractor.extractIdentityKey();
        keyExtractor.extractLastSignedPreKey();
        keyExtractor.extractPreKeys();
    }

    public static void main(Application application, ClassLoader classLoader)
    {
        main(new String[] {""});
    }

    public static void main(String args[])
    {
        Logger.log("Opening Axolotl database");
        SQLiteDatabase database = SQLiteDatabase.openDatabase(AXOLOTL_DATABASE_PATH,
            null, SQLiteDatabase.OPEN_READONLY);
        Logger.log("Extracting keys");
        extractAllKeys(database);
        Logger.log("Closing database");
        database.close();
    }
}

