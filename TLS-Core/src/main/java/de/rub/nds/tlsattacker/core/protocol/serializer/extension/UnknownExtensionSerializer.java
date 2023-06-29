/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.UnknownExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownExtensionSerializer extends ExtensionSerializer<UnknownExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final UnknownExtensionMessage msg;

    public UnknownExtensionSerializer(UnknownExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing UnknownExtensionMessage");
        if (hasExtensionData(msg)) {
            writeExtensionData(msg);
        }
        return getAlreadySerialized();
    }

    private boolean hasExtensionData(UnknownExtensionMessage msg) {
        return msg.getExtensionData() != null;
    }

    private void writeExtensionData(UnknownExtensionMessage msg) {
        appendBytes(msg.getExtensionData().getValue());
        LOGGER.debug("ExtensionData: {}", msg.getExtensionData().getValue());
    }
}
