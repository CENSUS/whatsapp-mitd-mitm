
import java.io.File;
import java.io.IOException;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Array;
import java.util.LinkedHashSet;
import java.util.HashMap;

import android.util.Base64;


public class WatlsPskExtract
{
    private static final String WATLS_SESSIONS_DIRNAME = "/storage/emulated/0/Android/data/com.whatsapp/cache/watls-sessions";

    private static Class<?> WtPersistentSessionClass;
    private static Field WtPersistentSessionClassSniField;
    private static Field WtPersistentSessionClassPsksField;

    private static Class<?> WtCachedPskClass;
    private static Field WtCachedPskClassSniField;
    private static Field WtCachedPskClassPskValField;
    private static Field WtCachedPskCertsIdField;


    private static void log(String message)
    {
        System.out.println(String.format("[*] %s", message));
    }


    private static String toHex(byte[] data)
    {
        StringBuilder hexBuilder = new StringBuilder();

        for(int i = 0; i < data.length; i++)
            hexBuilder.append(String.format("%02x", data[i]));

        return hexBuilder.toString();
    }


    private static void extractWatlsPsks(File file)
        throws Exception // IOException, ClassNotFoundException
    {
        //
        // Read `WtPersistentSession' object from given file.
        //
        FileInputStream fileInputStream = new FileInputStream(file);
        ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
        Object session = objectInputStream.readObject();
        objectInputStream.close();
        fileInputStream.close();

        //
        // Read SNI (i.e. hostname) from the top-level `WtPersistentSession'
        // object. Each `WtCachedPsk' also comes with its own `sni' field.
        //
        String sni = (String)ReflectionAPI.getFieldValue(WtPersistentSessionClassSniField, session);
        log(String.format("Top-level SNI %s", sni));

        //
        // Read array of PSKs for this session. Each element in this array is a
        // `WtCachedPsk' instance.
        //
        @SuppressWarnings("unchecked") LinkedHashSet<Object> psks = (LinkedHashSet<Object>)ReflectionAPI.getFieldValue(WtPersistentSessionClassPsksField, session);

        for(Object psk : psks)
        {
            Byte certsId  = (Byte)ReflectionAPI.getFieldValue(WtCachedPskCertsIdField, psk);
            String pskSni = (String)ReflectionAPI.getFieldValue(WtCachedPskClassSniField, psk);
            byte[] pskValue = (byte[])ReflectionAPI.getFieldValue(WtCachedPskClassPskValField, psk);
            log(String.format("Id %x SNI %s PSK %s", certsId.byteValue(), pskSni, toHex(pskValue)));
        }
    }


    public static void main(String args[])
    {
        try
        {
            //
            // Resovle `WtPersistentSession' and its fields.
            //
            WtPersistentSessionClass = ReflectionAPI.getClass("com.whatsapp.watls13.WtPersistentSession");
            WtPersistentSessionClassSniField = ReflectionAPI.getField(WtPersistentSessionClass, "sni");
            WtPersistentSessionClassPsksField = ReflectionAPI.getField(WtPersistentSessionClass, "psks");

            //
            // Resolve `WtCachedPsk' and its fields.
            //
            WtCachedPskClass = ReflectionAPI.getClass("com.whatsapp.net.tls13.WtCachedPsk");
            WtCachedPskClassSniField = ReflectionAPI.getField(WtCachedPskClass, "sni");
            WtCachedPskClassPskValField = ReflectionAPI.getField(WtCachedPskClass, "pskVal");
            WtCachedPskCertsIdField = ReflectionAPI.getField(WtCachedPskClass, "certsID");

            //
            // When no arguments are given, list all files under WhatsApp's
            // "watls-sessions" directory, parse each file and print the cached
            // TLS 1.3 PSKs.
            //
            if(args.length == 0)
            {
                log(String.format("Listing WaTLS sessions in %s", WATLS_SESSIONS_DIRNAME));

                for(File watlsSessionFile : new File(WATLS_SESSIONS_DIRNAME).listFiles())
                {
                    if(watlsSessionFile.isFile())
                    {
                        log(String.format("Extracting PSKs from WaTLS session %s", watlsSessionFile.toString()));
                        extractWatlsPsks(watlsSessionFile);
                    }
                }
            }
            //
            // Each argument is assumed to be the full path to a file holding a
            // serialized WaTLS session.
            //
            else
            {
                for(String watlsSessionFileName : args)
                {
                    log(String.format("Extract PSKs from WaTLS session %s", watlsSessionFileName));
                    extractWatlsPsks(new File(watlsSessionFileName));
                }
            }
        }
        catch(Exception e)
        {
            System.out.println(e.toString());
        }
    }
}

