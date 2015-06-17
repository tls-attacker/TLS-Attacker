/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.extension.handlers;

import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.tls.protocol.extension.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class EllipticCurvesExtensionHandler extends ExtensionHandler<EllipticCurvesExtensionMessage> {

    private static EllipticCurvesExtensionHandler instance;

    /**
     * byte length of the supported elliptic curves length
     */
    public static final int SUPPORTED_ELLIPTIC_CURVES_LENGTH = 2;

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
	byte[] curves = null;
	for (NamedCurve curve : extension.getSupportedCurvesConfig()) {
	    curves = ArrayConverter.concatenate(curves, curve.getValue());
	}

	extension.setExtensionType(ExtensionType.ELLIPTIC_CURVES.getValue());
	extension.setSupportedCurves(curves);
	extension.setSupportedCurvesLength(curves.length);
	extension.setExtensionLength(extension.getSupportedCurvesLength().getValue() + ExtensionByteLength.EXTENSIONS);

	byte[] ecExtensionBytes = ArrayConverter.concatenate(extension.getExtensionType().getValue(), ArrayConverter
		.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), ArrayConverter
		.intToBytes(extension.getSupportedCurvesLength().getValue(), SUPPORTED_ELLIPTIC_CURVES_LENGTH),
		extension.getSupportedCurves().getValue());

	extension.setExtensionBytes(ecExtensionBytes);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }
}
