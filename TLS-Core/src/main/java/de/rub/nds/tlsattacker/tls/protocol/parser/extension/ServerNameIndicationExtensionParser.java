/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.parser.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.ServerNameIndicationExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ServerNamePair;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class ServerNameIndicationExtensionParser extends ExtensionParser<ServerNameIndicationExtensionMessage>{

    public ServerNameIndicationExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public ServerNameIndicationExtensionMessage parse() {
        ServerNameIndicationExtensionMessage msg = new ServerNameIndicationExtensionMessage();
        parseExtensionType(msg);
        parseExtensionLength(msg);
        msg.setServerNameListLength(parseIntField(ExtensionByteLength.SERVER_NAME_LIST_LENGTH));
        msg.setServerNameListBytes(parseByteArrayField(msg.getServerNameListLength().getValue()));
        int position = 0;
        List<ServerNamePair> pairList = new LinkedList<>();
        while(position < msg.getServerNameListLength().getValue())
        {
            ServerNamePairParser parser = new ServerNamePairParser(position, msg.getServerNameListBytes().getValue());
            pairList.add(parser.parse());
        }
        msg.setServerNameList(pairList);
        return msg;
    }
    
}
