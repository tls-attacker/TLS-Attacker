/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.protocol.message.EncryptedExtensionsMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * This handler processes the EncryptedExtension messages, as defined in <a
 * href="https://tools.ietf.org/html/draft-ietf-tls-tls13-21#section-4.3.1">draft-ietf-tls-tls13-21
 * Section 4.3.1</a>
 */
public class EncryptedExtensionsHandler
        extends HandshakeMessageHandler<EncryptedExtensionsMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EncryptedExtensionsHandler(TlsContext tlsContext) {
        super(tlsContext);
    }

    @Override
    public void adjustContext(EncryptedExtensionsMessage message) {
        if (message.getExtensions() != null) {
            LOGGER.debug("Adjusting for EncryptedExtensions:");
            for (ExtensionMessage extension : message.getExtensions()) {
                LOGGER.debug("Adjusting " + message.toCompactString());
                Handler handler = extension.getHandler(tlsContext);
                handler.adjustContext(extension);
            }

            warnOnConflictingExtensions();
        }
    }

    private void warnOnConflictingExtensions() {
        if (tlsContext.getTalkingConnectionEndType()
                == tlsContext.getChooser().getMyConnectionPeer()) {
            if (tlsContext.isExtensionNegotiated(ExtensionType.MAX_FRAGMENT_LENGTH)
                    && tlsContext.isExtensionNegotiated(ExtensionType.RECORD_SIZE_LIMIT)) {
                LOGGER.warn("Server sent max_fragment_length AND record_size_limit extensions");
            }
        }
    }
}
