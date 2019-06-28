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
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import java.util.LinkedList;
import java.util.List;

public class AlpnExtensionParser extends ExtensionParser<AlpnExtensionMessage> {

    public AlpnExtensionParser(int startposition, byte[] array) {
        super(startposition, array);
    }

    @Override
    public void parseExtensionMessageContent(AlpnExtensionMessage msg) {
        msg.setAlpnExtensionLength(parseIntField(ExtensionByteLength.ALPN_EXTENSION_LENGTH));
        byte[] anouncedProtocols = parseByteArrayField(msg.getAlpnExtensionLength().getValue());
        msg.setAlpnAnnouncedProtocols(anouncedProtocols);
        List<AlpnEntry> entryList = new LinkedList<>();
        int pointer = 0;
        while (pointer < anouncedProtocols.length) {
            AlpnEntryParser parser = new AlpnEntryParser(pointer, anouncedProtocols);
            entryList.add(parser.parse());
            pointer = parser.getPointer();
        }
        msg.setAlpnEntryList(entryList);
    }

    @Override
    protected AlpnExtensionMessage createExtensionMessage() {
        return new AlpnExtensionMessage();
    }

}
