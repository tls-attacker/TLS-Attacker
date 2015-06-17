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
import de.rub.nds.tlsattacker.tls.protocol.extension.messages.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.util.ArrayConverter;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class SignatureAndHashAlgorithmsExtensionHandler extends
	ExtensionHandler<SignatureAndHashAlgorithmsExtensionMessage> {

    private static SignatureAndHashAlgorithmsExtensionHandler instance;

    public static final int SIGNATURE_AND_HASH_ALGORITHMS_LENGTH = 2;

    private SignatureAndHashAlgorithmsExtensionHandler() {

    }

    public static SignatureAndHashAlgorithmsExtensionHandler getInstance() {
	if (instance == null) {
	    instance = new SignatureAndHashAlgorithmsExtensionHandler();
	}
	return instance;
    }

    /**
     * @param extension
     */
    @Override
    public void initializeClientHelloExtension(SignatureAndHashAlgorithmsExtensionMessage extension) {
	byte[] algorithms = null;
	for (SignatureAndHashAlgorithm algorithm : extension.getSignatureAndHashAlgorithmsConfig()) {
	    algorithms = ArrayConverter.concatenate(algorithms, algorithm.getValue());
	}

	extension.setExtensionType(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue());
	extension.setSignatureAndHashAlgorithms(algorithms);
	extension.setSignatureAndHashAlgorithmsLength(algorithms.length);
	extension.setExtensionLength(extension.getSignatureAndHashAlgorithmsLength().getValue()
		+ ExtensionByteLength.EXTENSIONS);

	byte[] extensionBytes = ArrayConverter.concatenate(extension.getExtensionType().getValue(), ArrayConverter
		.intToBytes(extension.getExtensionLength().getValue(), ExtensionByteLength.EXTENSIONS), ArrayConverter
		.intToBytes(extension.getSignatureAndHashAlgorithmsLength().getValue(),
			SIGNATURE_AND_HASH_ALGORITHMS_LENGTH), extension.getSignatureAndHashAlgorithms().getValue());

	extension.setExtensionBytes(extensionBytes);
    }

    @Override
    public int parseExtension(byte[] message, int pointer) {
	throw new UnsupportedOperationException("Not supported yet.");
    }
}
