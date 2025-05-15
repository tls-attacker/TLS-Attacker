/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.DebugExtensionMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DebugExtensionSerializer extends ExtensionSerializer<DebugExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final DebugExtensionMessage message;

    public DebugExtensionSerializer(DebugExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing DebugExtensionMessage");
        serializeDebugContent(message);
        return getAlreadySerialized();
    }

    private void serializeDebugContent(DebugExtensionMessage msg) {
        appendBytes(msg.getDebugContent().getValue().getBytes(StandardCharsets.ISO_8859_1));
        LOGGER.debug(
                "Debug Message: {}",
                msg.getDebugContent().getValue().getBytes(StandardCharsets.ISO_8859_1));
    }
}
