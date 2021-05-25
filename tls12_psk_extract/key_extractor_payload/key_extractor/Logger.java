import android.util.Log;
import android.os.Process;

public class Logger
{
    private static final String LOG_TAG = "CENSUS";

    private static final int uid = Process.myUid();

    public static void log(String message)
    {
        //
        // Quick hack to determine whether we are running within the context of
        // an application, or standalone from the command line. In the former
        // case we use the Android logger to write messages, in the latter the
        // system console.
        //
        if(uid >= Process.FIRST_APPLICATION_UID && uid <= Process.LAST_APPLICATION_UID)
            Log.i(LOG_TAG, message);
        else
            System.out.println(message);
    }
}

