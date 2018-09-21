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
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SupportedVersionsExtensionMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SupportedVersionsExtensionSerializer extends ExtensionSerializer<SupportedVersionsExtensionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SupportedVersionsExtensionMessage msg;

    public SupportedVersionsExtensionSerializer(SupportedVersionsExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing SupportedVersionsExtensionMessage");
        if (msg.getSupportedVersionsLength() == null || msg.getSupportedVersions().getValue() == null) {
            writeSupportedVersions(msg);
        } else {
            writeSupportedVersionsLength(msg);
            writeSupportedVersions(msg);
        }
        return getAlreadySerialized();
    }

    private void writeSupportedVersionsLength(SupportedVersionsExtensionMessage msg) {
        appendInt(msg.getSupportedVersionsLength().getValue(), ExtensionByteLength.SUPPORTED_PROTOCOL_VERSIONS_LENGTH);
        LOGGER.debug("SupportedVersionsLength: " + msg.getSupportedVersionsLength().getValue());
    }

    private void writeSupportedVersions(SupportedVersionsExtensionMessage msg) {
        appendBytes(msg.getSupportedVersions().getValue());
        LOGGER.debug("SupportedVersions: " + ArrayConverter.bytesToHexString(msg.getSupportedVersions().getValue()));
    }
}
