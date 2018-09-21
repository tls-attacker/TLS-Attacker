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
import de.rub.nds.tlsattacker.core.protocol.message.extension.MaxFragmentLengthExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class MaxFragmentLengthExtensionSerializer extends ExtensionSerializer<MaxFragmentLengthExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final MaxFragmentLengthExtensionMessage msg;

    public MaxFragmentLengthExtensionSerializer(MaxFragmentLengthExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing MaxFragmentLengthExtensionMessage");
        writeMaxFragmentLength(msg);
        return getAlreadySerialized();
    }

    private void writeMaxFragmentLength(MaxFragmentLengthExtensionMessage msg) {
        appendBytes(msg.getMaxFragmentLength().getValue());
        LOGGER.debug("MaxFragmentLength: " + ArrayConverter.bytesToHexString(msg.getMaxFragmentLength().getValue()));
    }
}
