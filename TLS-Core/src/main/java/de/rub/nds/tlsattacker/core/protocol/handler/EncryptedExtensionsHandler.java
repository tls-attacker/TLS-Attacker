/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.extension.ExtensionHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.factory.HandlerFactory;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.EncryptedExtensionsParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.EncryptedExtensionsPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.EncryptedExtensionsSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This handler processes the EncryptedExtension messages, as defined in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.3.1
 */
public class EncryptedExtensionsHandler extends HandshakeMessageHandler<EncryptedExtensionsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedExtensionsHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public EncryptedExtensionsParser getParser(byte[] message, int pointer) {
        return new EncryptedExtensionsParser(pointer, message, tlsContext.getLastRecordVersion(),
            tlsContext.getConfig());
    }

    @Override
    public EncryptedExtensionsPreparator getPreparator(EncryptedExtensionsMessage message) {
        return new EncryptedExtensionsPreparator(tlsContext.getChooser(), message);
    }

    @Override
    public EncryptedExtensionsSerializer getSerializer(EncryptedExtensionsMessage message) {
        return new EncryptedExtensionsSerializer(message, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public void adjustTLSContext(EncryptedExtensionsMessage message) {
        if (message.getExtensions() != null) {
            LOGGER.debug("Adjusting for EncryptedExtensions:");
            for (ExtensionMessage extension : message.getExtensions()) {
                LOGGER.debug("Adjusting " + message.toCompactString());
                ExtensionHandler handler =
                    HandlerFactory.getExtensionHandler(tlsContext, extension.getExtensionTypeConstant());
                handler.adjustTLSContext(extension);
            }

            warnOnConflictingExtensions();
        }
    }

    private void warnOnConflictingExtensions() {
        if (tlsContext.getTalkingConnectionEndType() == tlsContext.getChooser().getMyConnectionPeer()) {
            if (tlsContext.isExtensionNegotiated(ExtensionType.MAX_FRAGMENT_LENGTH)
                && tlsContext.isExtensionNegotiated(ExtensionType.RECORD_SIZE_LIMIT)) {
                LOGGER.warn("Server sent max_fragment_length AND record_size_limit extensions");
            }
        }
    }
}
