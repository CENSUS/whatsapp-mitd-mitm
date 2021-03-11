Java.perform(function() {

    var PROTOCOL_TREE_NODE_READER = "X.0Ea";
    var PROTOCOL_TREE_NODE_WRITER = "X.0Ec";
    var PROTOCOL_TREE_NODE = "X.0Md";

    var _String = Java.use("java.lang.String");
    var StringBuilder = Java.use("java.lang.StringBuilder");
    var StandardCharsets = Java.use("java.nio.charset.StandardCharsets");

    var Base64 = Java.use("android.util.Base64");

    var ProtocolTreeNodeReader = Java.use(PROTOCOL_TREE_NODE_READER);
    var ProtocolTreeNodeWriter = Java.use(PROTOCOL_TREE_NODE_WRITER);
    var ProtocolTreeNode = Java.use(PROTOCOL_TREE_NODE);


    function protocolTreeNodeToStringRecursive(protocolTreeNode, stringBuilder, depth) {

        if(protocolTreeNode == null)
            return "";

        var indent = "";

        for(var i = 0; i < depth; i++)
            indent += "    ";

        var name = protocolTreeNode._A00.value;
        var attributes = protocolTreeNode._A02.value;
        var data = protocolTreeNode._A01.value;
        var children = protocolTreeNode._A03.value;

        stringBuilder.append(indent);
        stringBuilder.append("<");
        stringBuilder.append(name);

        if(attributes != null && attributes.length > 0) {
            stringBuilder.append(" ");

            for(var i = 0; i < attributes.length; i++) {
                var key = attributes[i].A02.value;
                var value = attributes[i].A03.value;
                stringBuilder.append(key + "=\"" + value + "\"");

                if(i < attributes.length - 1)
                    stringBuilder.append(" ");
            }
        }

        if(data != null || children != null)
            stringBuilder.append(">\n");

        if(data != null) {
            stringBuilder.append(indent);
            stringBuilder.append(indent);
            stringBuilder.append(Base64.encodeToString(data, Base64.NO_WRAP.value));
            stringBuilder.append("\n");
        }

        if(children != null) {
            for(var i = 0; i < children.length; i++)
                protocolTreeNodeToStringRecursive(children[i], stringBuilder, depth + 1);
        }

        if(data != null || children != null) {
            stringBuilder.append(indent);
            stringBuilder.append("</");
            stringBuilder.append(name);
            stringBuilder.append(">");
        }
        else
            stringBuilder.append(" />");
        stringBuilder.append("\n");
    }

    function protocolTreeNodeToString(protocolTreeNode) {
        var stringBuilder = StringBuilder.$new();
        stringBuilder.append("\n");
        protocolTreeNodeToStringRecursive(protocolTreeNode, stringBuilder, 0);
        return stringBuilder.toString();
    }


    // ProtocolTreeNodeReader.readPacket()
    ProtocolTreeNodeReader.AE8.implementation = function() {
        var protocolTreeNode = this.AE8();
        console.log(">>> IN\n" + protocolTreeNodeToString(protocolTreeNode));
        return protocolTreeNode;
    }

    // ProtocolTreeNodeWriter.writePacket()
    ProtocolTreeNodeWriter.AXT.implementation = function(protocolTreeNode, unknown) {
        console.log("<<< OUT\n" + protocolTreeNodeToString(protocolTreeNode));
        return this.AXT(protocolTreeNode, unknown);
    }
});

