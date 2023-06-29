/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlpnExtensionHandler extends ExtensionHandler<AlpnExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AlpnExtensionHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustTLSExtensionContext(AlpnExtensionMessage message) {
        List<AlpnEntry> alpnEntryList = message.getAlpnEntryList();
        List<String> alpnStringList = new LinkedList<>();
        for (AlpnEntry entry : alpnEntryList) {
            alpnStringList.add(entry.getAlpnEntry().getValue());
        }
        if (tlsContext.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {

            tlsContext.setProposedAlpnProtocols(alpnStringList);
            LOGGER.debug("Adjustet the TLS context proposed ALPN protocols:");
            if (LOGGER.isEnabled(Level.DEBUG)) {
                for (String stringEntry : alpnStringList) {
                    LOGGER.debug(stringEntry);
                }
            }
        } else {
            if (alpnStringList.size() > 1) {
                LOGGER.warn(
                        "Server selected more than one protocol. We only set the first as selected.");
            }
            if (alpnStringList.isEmpty()) {
                LOGGER.warn("Server did not select an ALPN protocol.");
            } else {
                tlsContext.setSelectedAlpnProtocol(alpnStringList.get(0));
            }
        }
    }
}
