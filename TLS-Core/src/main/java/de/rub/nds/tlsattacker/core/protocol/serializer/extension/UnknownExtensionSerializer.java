/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
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
        LOGGER.debug("Serializing UnknoenExtensionMessage");
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
        LOGGER.debug("ExtensionData: " + ArrayConverter.bytesToHexString(msg.getExtensionData().getValue()));
    }
}
