/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedCurve;
import de.rub.nds.tlsattacker.core.exceptions.PreparationException;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.EllipticCurvesExtensionSerializer;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 *

 */
public class EllipticCurvesExtensionPreparator extends ExtensionPreparator<EllipticCurvesExtensionMessage> {

    private final EllipticCurvesExtensionMessage msg;

    public EllipticCurvesExtensionPreparator(Chooser chooser, EllipticCurvesExtensionMessage message,
            EllipticCurvesExtensionSerializer serializer) {
        super(chooser, message, serializer);
        msg = message;
    }

    @Override
    public void prepareExtensionContent() {
        LOGGER.debug("Preparing EllipticCurvesExtensionMessage");
        prepareEllipticCurves(msg);
        prepareSupportedCurvesLength(msg);
    }

    private void prepareEllipticCurves(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedCurves(createEllipticCurveArray());
        LOGGER.debug("SupportedCurves: " + ArrayConverter.bytesToHexString(msg.getSupportedCurves().getValue()));
    }

    private byte[] createEllipticCurveArray() {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        for (NamedCurve curve : chooser.getConfig().getNamedCurves()) {
            try {
                stream.write(curve.getValue());
            } catch (IOException ex) {
                throw new PreparationException("Could not write NamedCurve to byte[]", ex);
            }
        }
        return stream.toByteArray();
    }

    private void prepareSupportedCurvesLength(EllipticCurvesExtensionMessage msg) {
        msg.setSupportedCurvesLength(msg.getSupportedCurves().getValue().length);
        LOGGER.debug("SupportedCurvesLength: " + msg.getSupportedCurvesLength().getValue());
    }
}
