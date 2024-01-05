/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class AlpnExtensionParser extends ExtensionParser<AlpnExtensionMessage> {

    public AlpnExtensionParser(InputStream stream, TlsContext tlsContext) {
        super(stream, tlsContext);
    }

    @Override
    public void parse(AlpnExtensionMessage msg) {
        msg.setProposedAlpnProtocolsLength(
                parseIntField(ExtensionByteLength.ALPN_EXTENSION_LENGTH));
        byte[] proposedProtocol =
                parseByteArrayField(msg.getProposedAlpnProtocolsLength().getValue());
        msg.setProposedAlpnProtocols(proposedProtocol);
        List<AlpnEntry> entryList = new LinkedList<>();
        ByteArrayInputStream innerStream = new ByteArrayInputStream(proposedProtocol);
        while (innerStream.available() > 0) {
            AlpnEntryParser parser = new AlpnEntryParser(innerStream);
            AlpnEntry entry = new AlpnEntry();
            parser.parse(entry);
            entryList.add(entry);
        }
        msg.setAlpnEntryList(entryList);
    }
}
