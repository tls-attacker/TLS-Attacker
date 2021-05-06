/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
        }
        // executes even if record_size_limit was (contrary to the specification) not sent with encrypted extensions
        adjustConflictingExtensions();
    }

    private void adjustConflictingExtensions() {
        // RFC 8449 says 'A client MUST treat receipt of both "max_fragment_length" and "record_size_limit" as a fatal
        // error, and it SHOULD generate an "illegal_parameter" alert.', ignoring that for now and disabling
        // max_fragment_length
        if (tlsContext.isExtensionNegotiated(ExtensionType.MAX_FRAGMENT_LENGTH)
            && tlsContext.isExtensionNegotiated(ExtensionType.RECORD_SIZE_LIMIT)) {
            LOGGER.warn(
                "Found max_fragment_length and record_size_limit extensions, disabling max_fragment_length in context");
            tlsContext.setMaxFragmentLength(null);
        }
    }
}
