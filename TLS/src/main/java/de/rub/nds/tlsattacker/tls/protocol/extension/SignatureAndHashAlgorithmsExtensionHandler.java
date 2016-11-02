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
import de.rub.nds.tlsattacker.tls.constants.SignatureAndHashAlgorithm;
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
	byte[] algorithms = new byte[0];
	for (SignatureAndHashAlgorithm algorithm : extension.getSignatureAndHashAlgorithmsConfig()) {
	    algorithms = ArrayConverter.concatenate(algorithms, algorithm.getByteValue());
	}

	extension.setExtensionType(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS.getValue());
	extension.setSignatureAndHashAlgorithms(algorithms);
	extension.setSignatureAndHashAlgorithmsLength(algorithms != null ? algorithms.length : 0);
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
