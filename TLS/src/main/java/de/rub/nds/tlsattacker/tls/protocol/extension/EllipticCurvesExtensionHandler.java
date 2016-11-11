/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.extension;

import de.rub.nds.tlsattacker.tls.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EllipticCurvesExtensionHandler extends ExtensionHandler<EllipticCurvesExtensionMessage> {

    private static EllipticCurvesExtensionHandler instance;

    /**
     * byte length of the supported elliptic curves length
     */
    public static final int SUPPORTED_ELLIPTIC_CURVES_LENGTH = 2;// TODO can

    // this be a
    // field of the
    // Message and
    // modifieable?

    private EllipticCurvesExtensionHandler() {

    }

    public static EllipticCurvesExtensionHandler getInstance() {
        if (instance == null) {
            instance = new EllipticCurvesExtensionHandler();
        }
        return instance;
    }

    /**
     * @param extension
     */
    @Override
    public void initializeClientHelloExtension(EllipticCurvesExtensionMessage extension) {
        byte[] curves = new byte[0];
        for (NamedCurve curve : extension.getSupportedCurvesConfig()) {
            curves = ArrayConverter.concatenate(curves, curve.getValue());
        }

        extension.setExtensionType(ExtensionType.ELLIPTIC_CURVES.getValue());
        extension.setSupportedCurves(curves);
        extension.setSupportedCurvesLength(curves != null ? curves.length : 0);
        extension.setExtensionLength(extension.getSupportedCurvesLength().getValue() + ExtensionByteLength.EXTENSIONS);

        byte[] ecExtensionBytes = ArrayConverter.concatenate(extension.getExtensionType().getValue(), ArrayConverter
                .intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), ArrayConverter
                .intToBytes(extension.getSupportedCurvesLength().getValue(), SUPPORTED_ELLIPTIC_CURVES_LENGTH),
                extension.getSupportedCurves().getValue());

        extension.setExtensionBytes(ecExtensionBytes);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
        throw new UnsupportedOperationException("Elliptic curve extension handler not supported yet.");
    }
}
