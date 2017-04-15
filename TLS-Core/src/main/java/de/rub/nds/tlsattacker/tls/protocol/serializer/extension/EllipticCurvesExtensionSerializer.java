/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.serializer.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.message.extension.EllipticCurvesExtensionMessage;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class EllipticCurvesExtensionSerializer extends ExtensionSerializer<EllipticCurvesExtensionMessage> {

    private final EllipticCurvesExtensionMessage message;

    public EllipticCurvesExtensionSerializer(EllipticCurvesExtensionMessage message) {
        super(message);
        this.message = message;
    }

    @Override
    public byte[] serializeExtensionContent() {
        appendInt(message.getSupportedCurvesLength().getValue(), ExtensionByteLength.SUPPORTED_ELLIPTIC_CURVES_LENGTH);
        appendBytes(message.getSupportedCurves().getValue());
        return getAlreadySerialized();
    }
}
