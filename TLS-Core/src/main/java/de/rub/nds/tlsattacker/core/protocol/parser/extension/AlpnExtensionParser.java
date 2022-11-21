/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import java.util.LinkedList;
import java.util.List;

public class AlpnExtensionParser extends ExtensionParser<AlpnExtensionMessage> {

    public AlpnExtensionParser(int startposition, byte[] array, Config config) {
        super(startposition, array, config);
    }

    @Override
    public void parseExtensionMessageContent(AlpnExtensionMessage msg) {
        msg.setProposedAlpnProtocolsLength(parseIntField(ExtensionByteLength.ALPN_EXTENSION_LENGTH));
        byte[] proposedProtocol = parseByteArrayField(msg.getProposedAlpnProtocolsLength().getValue());
        msg.setProposedAlpnProtocols(proposedProtocol);
        List<AlpnEntry> entryList = new LinkedList<>();
        int pointer = 0;
        while (pointer < proposedProtocol.length) {
            AlpnEntryParser parser = new AlpnEntryParser(pointer, proposedProtocol);
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
