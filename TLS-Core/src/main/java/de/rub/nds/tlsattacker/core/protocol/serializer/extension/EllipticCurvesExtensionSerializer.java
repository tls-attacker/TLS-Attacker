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
        writeSupportedCurvesLength(msg);
        writeSupportedCurves(msg);
        return getAlreadySerialized();
    }

    private void writeSupportedCurvesLength(EllipticCurvesExtensionMessage msg) {
        appendInt(msg.getSupportedCurvesLength().getValue(), ExtensionByteLength.SUPPORTED_ELLIPTIC_CURVES);
        LOGGER.debug("SupportedCurvesLength: " + msg.getSupportedCurvesLength().getValue());
    }

    private void writeSupportedCurves(EllipticCurvesExtensionMessage msg) {
        appendBytes(msg.getSupportedCurves().getValue());
        LOGGER.debug("SupportedCurves: " + ArrayConverter.bytesToHexString(msg.getSupportedCurves().getValue()));
    }
}
