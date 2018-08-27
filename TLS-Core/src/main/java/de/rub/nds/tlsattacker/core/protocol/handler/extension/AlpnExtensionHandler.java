/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.AlpnExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.AlpnExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.AlpnExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.AlpnExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AlpnExtensionHandler extends ExtensionHandler<AlpnExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AlpnExtensionHandler(TlsContext context) {
        super(context);
    }

    @Override
    public AlpnExtensionParser getParser(byte[] message, int pointer) {
        return new AlpnExtensionParser(pointer, message);
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
        context.setAlpnAnnouncedProtocols(message.getAlpnAnnouncedProtocols().getValue());
        LOGGER.debug("Adjustet the TLS context ALPN announced protocols to "
                + ArrayConverter.bytesToHexString(message.getAlpnAnnouncedProtocols()));
    }

}
