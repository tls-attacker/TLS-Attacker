/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.PaddingExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PaddingExtensionSerializer extends ExtensionSerializer<PaddingExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PaddingExtensionMessage message;

    public PaddingExtensionSerializer(PaddingExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendBytes(message.getPaddingBytes().getValue());
        LOGGER.debug(
                "Serialized PaddingExtension with {} padding bytes.",
                message.getPaddingBytes().getValue().length);
        return getAlreadySerialized();
    }
}
