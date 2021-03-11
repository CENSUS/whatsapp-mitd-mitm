Java.perform(function() {
    var Debug = Java.use("android.os.Debug");
    Debug.dumpHprofData("/data/data/com.whatsapp/whatsapp.bin");
});
