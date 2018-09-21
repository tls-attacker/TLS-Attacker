/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtendedMasterSecretExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtendedMasterSecretExtensionSerializer extends ExtensionSerializer<ExtendedMasterSecretExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtendedMasterSecretExtensionSerializer(ExtendedMasterSecretExtensionMessage message) {
        super(message);
    }

    /**
     * Serializes the extended master secret extension. There is no data to
     * serialize; it is a "just present" extension.
     *
     * @return Serialized bytes of the extended master secret extension
     */
    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serialized the extended master secret extension.");
        return getAlreadySerialized();
    }

}
