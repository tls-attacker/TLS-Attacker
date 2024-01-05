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
import de.rub.nds.tlsattacker.core.protocol.message.extension.ECPointFormatExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ECPointFormatExtensionSerializer
        extends ExtensionSerializer<ECPointFormatExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ECPointFormatExtensionMessage msg;

    public ECPointFormatExtensionSerializer(ECPointFormatExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing ECPointFormatExtensionMessage");
        writePointFormatsLength(msg);
        writePointFormats(msg);
        return getAlreadySerialized();
    }

    private void writePointFormatsLength(ECPointFormatExtensionMessage msg) {
        appendInt(msg.getPointFormatsLength().getValue(), ExtensionByteLength.EC_POINT_FORMATS);
        LOGGER.debug("PointFormatsLength: " + msg.getPointFormatsLength().getValue());
    }

    private void writePointFormats(ECPointFormatExtensionMessage msg) {
        appendBytes(msg.getPointFormats().getValue());
        LOGGER.debug("PointFormats: {}", msg.getPointFormats().getValue());
    }
}
