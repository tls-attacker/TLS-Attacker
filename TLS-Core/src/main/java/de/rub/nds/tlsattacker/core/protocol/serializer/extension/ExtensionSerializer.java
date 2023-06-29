/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * @param <T> The ExtensionMessage that should be serialized
 */
public abstract class ExtensionSerializer<T extends ExtensionMessage> extends Serializer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ExtensionMessage msg;

    public ExtensionSerializer(T message) {
        super();
        this.msg = message;
    }

    @Override
    protected byte[] serializeBytes() {
        writeType();
        writeLength();
        writeContent();

        return getAlreadySerialized();
    }

    private void writeType() {
        appendBytes(msg.getExtensionType().getValue());
        LOGGER.debug("ExtensionType: {}", msg.getExtensionType().getValue());
    }

    private void writeLength() {
        appendInt(msg.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS_LENGTH);
        LOGGER.debug("extensionLength: " + msg.getExtensionLength().getValue());
    }

    private void writeContent() {
        appendBytes(msg.getExtensionContent().getValue());
        LOGGER.debug("ExtensionContent: {}", msg.getExtensionContent().getValue());
    }

    public abstract byte[] serializeExtensionContent();
}
