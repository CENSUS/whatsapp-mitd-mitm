//
// Determine WhatsApp version installed on attacker's device.
//
function _version() {
    var version = null;

    Java.perform(function() {
        var ActivityThread = Java.use("android.app.ActivityThread");
        var context = ActivityThread.currentApplication();
        var sharedPreferences = context.getSharedPreferences("com.whatsapp_preferences_light", 0);
        version = sharedPreferences.getString("version", null);
    });

    return version;
}

rpc.exports = {
    version: function() {
        return _version();
    }
}
