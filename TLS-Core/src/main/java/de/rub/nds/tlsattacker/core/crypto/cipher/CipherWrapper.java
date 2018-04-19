/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CipherWrapper {

    protected static final Logger LOGGER = LogManager.getLogger(CipherWrapper.class.getName());

    public static EncryptionCipher getEncryptionCipher(CipherAlgorithm cipherAlg) {
        if (cipherAlg.getJavaName() != null) {
            return new JavaCipher(cipherAlg);
        } else if (cipherAlg == CipherAlgorithm.NULL) {
            return new NullCipher();
        } else {
            LOGGER.warn("Cipher:" + cipherAlg + " is not supported - Using NullCipher!");
            return new NullCipher();
        }
    }

    public static DecryptionCipher getDecryptionCipher(CipherAlgorithm cipherAlg) {
        if (cipherAlg.getJavaName() != null) {
            return new JavaCipher(cipherAlg);
        } else if (cipherAlg == CipherAlgorithm.NULL) {
            return new NullCipher();
        } else {
            LOGGER.warn("Cipher:" + cipherAlg + " is not supported - Using NullCipher!");
            return new NullCipher();
        }
    }

}
