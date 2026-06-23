/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EncryptedClientHelloEncryptedExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.ExtensionSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EncryptedClientHelloEncryptedExtensionSerializer
        extends ExtensionSerializer<EncryptedClientHelloEncryptedExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final EncryptedClientHelloEncryptedExtensionMessage msg;

    public EncryptedClientHelloEncryptedExtensionSerializer(
            EncryptedClientHelloEncryptedExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(msg.getEchConfigsLength().getValue(), ExtensionByteLength.ECH_CONFIG_LIST_LENGTH);
        LOGGER.debug("Ech Configs Length: {}", msg.getEchConfigsLength().getValue());
        for (EchConfig config : msg.getEchConfigs()) {
            appendBytes(config.getEchConfigBytes());
        }
        return getAlreadySerialized();
    }
}
