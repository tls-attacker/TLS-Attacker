/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.alpn.AlpnEntry;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.AlpnExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.AlpnExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.AlpnExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlpnExtensionHandler extends ExtensionHandler<AlpnExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AlpnExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public AlpnExtensionParser getParser(byte[] message, int pointer, Config config) {
        return new AlpnExtensionParser(pointer, message, config);
    }

    @Override
    public AlpnExtensionPreparator getPreparator(AlpnExtensionMessage message) {
        return new AlpnExtensionPreparator(context.getChooser(), message, getSerializer(message));
    }

    @Override
    public AlpnExtensionSerializer getSerializer(AlpnExtensionMessage message) {
        return new AlpnExtensionSerializer(message);
    }

    @Override
    public void adjustTLSExtensionContext(AlpnExtensionMessage message) {
        List<AlpnEntry> alpnEntryList = message.getAlpnEntryList();
        List<String> alpnStringList = new LinkedList<>();
        for (AlpnEntry entry : alpnEntryList) {
            alpnStringList.add(entry.getAlpnEntry().getValue());
        }
        if (context.getTalkingConnectionEndType() == ConnectionEndType.CLIENT) {

            context.setProposedAlpnProtocols(alpnStringList);
            LOGGER.debug("Adjustet the TLS context proposed ALPN protocols:");
            if (LOGGER.isEnabled(Level.DEBUG)) {
                for (String stringEntry : alpnStringList) {
                    LOGGER.debug(stringEntry);
                }
            }
        } else {
            if (alpnStringList.size() > 1) {
                LOGGER.warn("Server selected more than one protocol. We only set the first as selected.");
            }
            if (alpnStringList.isEmpty()) {
                LOGGER.warn("Server did not select an ALPN protocol.");
            } else {
                context.setSelectedAlpnProtocol(alpnStringList.get(0));
            }
        }
    }
}
