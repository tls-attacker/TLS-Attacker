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
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KS.KeySharePair;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.KeyShareExtensionMessage;
import java.util.LinkedList;
import java.util.List;

/**
 * @author Nurullah Erinola
 */
public class KeyShareExtensionParser extends ExtensionParser<KeyShareExtensionMessage> {

    private final boolean isServer;

    public KeyShareExtensionParser(int startposition, byte[] array, boolean isServer) {
        super(startposition, array);
        this.isServer = isServer;
    }

    @Override
    public void parseExtensionMessageContent(KeyShareExtensionMessage msg) {
        if (isServer != true) {
            msg.setKeyShareListLength(parseIntField(ExtensionByteLength.KEY_SHARE_LIST_LENGTH));
            msg.setKeyShareListBytes(parseByteArrayField(msg.getKeyShareListLength().getValue()));
        } else {
            msg.setKeyShareListBytes(parseByteArrayField(msg.getExtensionLength().getValue()));
        }
        int position = 0;
        List<KeySharePair> pairList = new LinkedList<>();
        while (position < msg.getKeyShareListLength().getValue()) {
            KeySharePairParser parser = new KeySharePairParser(position, msg.getKeyShareListBytes().getValue());
            pairList.add(parser.parse());
        }
        msg.setKeyShareList(pairList);
    }

    @Override
    protected KeyShareExtensionMessage createExtensionMessage() {
        return new KeyShareExtensionMessage();
    }
}
