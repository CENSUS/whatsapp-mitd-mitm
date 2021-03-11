Java.perform(function() {
    var RESUMPTION_MASTER_SECRET_EVENT = "X.2oZ";
    var WATLS_TRUST_MANAGER = "X.35n";
    var WATLS_STATE = "X.2on";

    var _String = Java.use("java.lang.String");
    var HashMap = Java.use("java.util.HashMap");
    var MapEntry = Java.use("java.util.Map$Entry");
    var ReflectArray = Java.use("java.lang.reflect.Array");
    var Integer = Java.use("java.lang.Integer");
    var Exception = Java.use("java.lang.Exception");
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    var AllowAllHostnameVerifier = Java.use("org.apache.http.conn.ssl.AllowAllHostnameVerifier");

    var Log = Java.use("android.util.Log");
    var Base64 = Java.use("android.util.Base64");

    var ResumptionMasterSecretEvent = Java.use(RESUMPTION_MASTER_SECRET_EVENT);
    var WatlsTrustManager = Java.use(WATLS_TRUST_MANAGER);
    var WatlsState = Java.use(WATLS_STATE);


    function hexdump(bytearray) {
        var length = ReflectArray.getLength(bytearray);
        var s = "";
        for(var i = 0; i < length; i++)
        {
            var c = ReflectArray.getByte(bytearray, i);
            if(i != 0 && i % 32 == 0)
                s += "\n";
            s += Integer.toHexString(c & 0x000000ff) + " ";
        }
        return s;
    }


    ////////// CERTIFICATE CHAIN AND HOSTNAME VERIFICATION //////////

    WatlsTrustManager.checkServerTrusted.implementation = function(certs, auth_type) {
        console.log("Verifying certificate chain :-( this shouldn't have happened!");
        // console.log(Log.getStackTraceString(Exception.$new()));
        this.checkServerTrusted(certs, auth_type);
    }

    HttpsURLConnection.setDefaultHostnameVerifier(AllowAllHostnameVerifier.$new());


    ////////// WATLS EVENT HANDLING //////////

    var implementation = ResumptionMasterSecretEvent.A00.implementation;

    ResumptionMasterSecretEvent.A00.implementation = function(_1, _2, _3, _4) {
        var ret = this.A00(_1, _2, _3, _4);

        // Second argument is the WaTLS state that stores all WaTLS related variables.
        var state = Java.cast(_2, WatlsState);

        // Map of TLS secrets.
        var hash_map = Java.cast(state.A0U.value, HashMap);
        var entry_set = hash_map.entrySet();
        var array = entry_set.toArray();

        array.forEach(function(entry) {
            entry = Java.cast(entry, MapEntry);
            console.log(entry.getKey() + " : " + hexdump(entry.getValue()));
        });

        //
        // Get the `WatlsUnserializedSSLSession' (`A0H') instance and from there
        // the `WtCachedPsk' (`A03') instance and from there the actual PSK value
        // as a byte array.
        //
        if(state.A0H.value != null && state.A0H.value.A03.value.pskVal.value != null)
            console.log("Chosen PSK is " + hexdump(state.A0H.value.A03.value.pskVal.value));
        else
            console.log("No PSK!");

        ResumptionMasterSecretEvent.A00.implementation = implementation;

        return ret;
    }
});


function connect(hostname) {
    Java.perform(function() {
        var MEDIA_DOWNLOAD_CONNECTION = "X.0DT";
        var MEDIA_DOWNLOAD_RESPONSE = "X.2jP";

        var MediaDownloadConnection = Java.use(MEDIA_DOWNLOAD_CONNECTION);
        var MediaDownloadResponse = Java.use(MEDIA_DOWNLOAD_RESPONSE);
        var mediaDownloadConnection = MediaDownloadConnection.A00(); // getInstance()

        var URL = Java.use("java.net.URL");
        var url = URL.$new("https://" + hostname);

        var mediaDownloadResponse = mediaDownloadConnection.A03(url, hostname, "GET");
        mediaDownloadResponse = Java.cast(mediaDownloadResponse, MediaDownloadResponse);

        console.log("Response code is " + mediaDownloadResponse.A2u()); // getResponseCode()

        mediaDownloadResponse.close();
    });
}


function connect_lan() {
    connect("192.168.1.100");
}

function connect_fath() {
    connect("media.fath6-1.fna.whatsapp.net");
}

