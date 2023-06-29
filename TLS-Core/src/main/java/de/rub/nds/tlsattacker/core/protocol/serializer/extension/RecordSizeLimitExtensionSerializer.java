/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.RecordSizeLimitExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RecordSizeLimitExtensionSerializer
        extends ExtensionSerializer<RecordSizeLimitExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final RecordSizeLimitExtensionMessage message;

    public RecordSizeLimitExtensionSerializer(RecordSizeLimitExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing RecordSizeLimitExtensionMessage");
        serializeRecordSizeLimit();

        return getAlreadySerialized();
    }

    private void serializeRecordSizeLimit() {
        appendBytes(message.getRecordSizeLimit().getValue());
        LOGGER.debug("RecordSizeLimit: {}", message.getRecordSizeLimit().getValue());
    }
}
