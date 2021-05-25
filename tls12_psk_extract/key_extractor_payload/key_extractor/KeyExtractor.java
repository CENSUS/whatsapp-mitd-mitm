import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.Date;

import android.util.Base64;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import com.google.protobuf.InvalidProtocolBufferException;


public class KeyExtractor
{
    private static final String KEYSTORE_PATH = "/data/data/com.whatsapp/shared_prefs/keystore.xml";

    private SQLiteDatabase database;

    public KeyExtractor(SQLiteDatabase database)
    {
        this.database = database;
    }


    //
    // Return hexadecimal dump of the given byte array.
    //
    public String hexdump(byte[] data, int bytesPerLine, String prefix)
    {
        StringBuilder dump = new StringBuilder(prefix);

        for(int i = 0; i < data.length; i++)
        {
            if(i != 0 && i % bytesPerLine == 0)
               dump.append(String.format("\n%s", prefix));
            dump.append(String.format("%02x", data[i]));
        }

        dump.append("\n");

        return dump.toString();
    }

    public String hexdump(byte[] data, String prefix)
    {
        return hexdump(data, 32, prefix);
    }


    //
    // Extract identity key.
    //
    public void extractIdentityKey()
    {
        String[] columns = new String[]
        {
            "public_Key",
            "private_key"
        };

        Cursor cursor = this.database.query("identities", columns,
            "recipient_id = -1 AND device_id = 0", null, null, null, null, null);

        if(cursor.moveToFirst())
        {
            Logger.log("Extracting identity key");
            Logger.log("\tPublic key");
            Logger.log(hexdump(cursor.getBlob(0), "\t\t"));
            Logger.log("\tPrivate key");
            Logger.log(hexdump(cursor.getBlob(1), "\t\t"));
        }
        else
        {
            Logger.log("Identity key not found");
        }

        cursor.close();
    }


    //
    // Extract last signed prekey.
    //
    public void extractLastSignedPreKey()
    {
        String[] columns = new String[]
        {
            "prekey_id",
            "record",
            "timestamp"
        };

        Cursor cursor = this.database.query("signed_prekeys", columns,
            null, null, null, null, null, null);

        if(cursor.moveToFirst())
        {
            Logger.log("Extracting last signed prekey");
            Logger.log(hexdump(cursor.getBlob(1), "\t"));

            try
            {
                SignedPreKey signedPreKey = SignedPreKey.parseFrom(cursor.getBlob(1));

                Logger.log("\tPublic key");
                Logger.log(hexdump(signedPreKey.getPublicKey().toByteArray(), "\t\t"));

                Logger.log("\tPrivate key");
                Logger.log(hexdump(signedPreKey.getPrivateKey().toByteArray(), "\t\t"));

                Logger.log("\tSignature");
                Logger.log(hexdump(signedPreKey.getSignature().toByteArray(), "\t\t"));
            }
            catch(InvalidProtocolBufferException exception)
            {
                Logger.log(exception.toString());
            }
        }
        else
        {
            Logger.log("Last signed prekey not found");
        }

        cursor.close();
    }


    //
    // Extract one-time prekeys.
    //
    public void extractPreKeys()
    {
        String[] columns = new String[]
        {
            "prekey_id",
            "record",
            "sent_to_server",
            "upload_timestamp"
        };

        Cursor cursor = this.database.query("prekeys", columns,
            null, null, null, null, null, null);

        Logger.log("Extracting prekeys");

        long i = 0;

        while(cursor.moveToNext())
        {
            long preKeyId = cursor.getLong(0);
            boolean uploaded = cursor.getLong(2) != 0;
            Date uploadDate = new Date(cursor.getLong(3) * 1000);

            Logger.log(String.format("\t%4d | Prekey %x | uploaded %s | %s",
                i, preKeyId, uploaded, uploadDate));

            try
            {
                Logger.log(hexdump(cursor.getBlob(1), "\t\t"));

                SignedPreKey signedPreKey = SignedPreKey.parseFrom(cursor.getBlob(1));

                Logger.log("\t\tPublic key");
                Logger.log(hexdump(signedPreKey.getPublicKey().toByteArray(), "\t\t\t"));

                Logger.log("\t\tPrivate key");
                Logger.log(hexdump(signedPreKey.getPrivateKey().toByteArray(), "\t\t\t"));
            }
            catch(InvalidProtocolBufferException exception)
            {
                Logger.log(exception.toString());
            }

            i += 1;
        }

        cursor.close();
    }


    //
    // Extract client's Noise key-pair.
    //
    public void extractNoiseKeyPair()
    {
        Logger.log("Extracting Noise key pair");

        try
        {
            File keystoreFile = new File(KEYSTORE_PATH);

            FileInputStream inputStream = new FileInputStream(keystoreFile);

            XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
            XmlPullParser parser = factory.newPullParser();

            parser.setInput(inputStream, null);

            int event = parser.getEventType();

            while(event != XmlPullParser.END_DOCUMENT)
            {
                if(event == XmlPullParser.START_TAG &&
                    parser.getName().equals("string") &&
                    parser.getAttributeValue(null, "name").equals("client_static_keypair"))
                {
                    parser.next();
                    Logger.log("\tClient Noise key-pair");
                    Logger.log(hexdump(Base64.decode(parser.getText(), 0), "\t\t"));
                    break;
                }
                event = parser.next();
            }
        }
        catch(FileNotFoundException exception)
        {
            Logger.log(exception.toString());
        }
        catch(XmlPullParserException exception)
        {
            Logger.log(exception.toString());
        }
        catch(IOException exception)
        {
            Logger.log(exception.toString());
        }
    }
}
