/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.EarlyDataExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * RFC draft-ietf-tls-tls13-21
 */
public class EarlyDataExtensionSerializer extends ExtensionSerializer<EarlyDataExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EarlyDataExtensionSerializer(EarlyDataExtensionMessage message) {
        super(message);
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing EarlyDataExtensionMessage");
        return getAlreadySerialized();
    }

}
