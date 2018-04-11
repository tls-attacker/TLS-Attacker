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
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;

public class EllipticCurvesExtensionSerializer extends ExtensionSerializer<EllipticCurvesExtensionMessage> {

    private final EllipticCurvesExtensionMessage msg;

    public EllipticCurvesExtensionSerializer(EllipticCurvesExtensionMessage message) {
        super(message);
        this.msg = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        LOGGER.debug("Serializing EllipticCurvesExtensionMessage");
        writeSupportedGroupsLength(msg);
        writeSupportedGroups(msg);
        return getAlreadySerialized();
    }

    private void writeSupportedGroupsLength(EllipticCurvesExtensionMessage msg) {
        appendInt(msg.getSupportedGroupsLength().getValue(), ExtensionByteLength.SUPPORTED_GROUPS);
        LOGGER.debug("SupportedGroupsLength: " + msg.getSupportedGroupsLength().getValue());
    }

    private void writeSupportedGroups(EllipticCurvesExtensionMessage msg) {
        appendBytes(msg.getSupportedGroups().getValue());
        LOGGER.debug("SupportedGroups: " + ArrayConverter.bytesToHexString(msg.getSupportedGroups().getValue()));
    }
}
