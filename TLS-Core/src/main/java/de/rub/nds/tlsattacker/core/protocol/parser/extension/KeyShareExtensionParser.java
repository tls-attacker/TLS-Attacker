/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Nurullah Erinola
 */
public class KeyShareExtensionParser extends ExtensionParser<KeyShareExtensionMessage> {

    private final ConnectionEnd connection;

    public KeyShareExtensionParser(int startposition, byte[] array, ConnectionEnd connection) {
        super(startposition, array);
        this.connection = connection;
    }

    @Override
    public void parseExtensionMessageContent(KeyShareExtensionMessage msg) {
        if (connection == ConnectionEnd.CLIENT) {
            msg.setKeyShareListLength(parseIntField(ExtensionByteLength.KEY_SHARE_LIST_LENGTH));
            msg.setKeyShareListBytes(parseByteArrayField(msg.getKeyShareListLength().getValue()));
        } else {
            msg.setKeyShareListBytes(parseByteArrayField(msg.getExtensionLength().getValue()));
            msg.setKeyShareListLength(msg.getKeyShareListBytes().getValue().length);
        }
        int position = 0;
        List<KeySharePair> pairList = new LinkedList<>();
        while (position < msg.getKeyShareListLength().getValue()) {
            KeySharePairParser parser = new KeySharePairParser(position, msg.getKeyShareListBytes().getValue());
            pairList.add(parser.parse());
            position = parser.getPointer();
        }
        msg.setKeyShareList(pairList);
    }

    @Override
    protected KeyShareExtensionMessage createExtensionMessage() {
        return new KeyShareExtensionMessage();
    }
}
