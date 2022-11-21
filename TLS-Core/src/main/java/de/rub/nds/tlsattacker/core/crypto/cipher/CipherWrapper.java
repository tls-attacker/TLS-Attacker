/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.cipher;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherAlgorithm;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CipherType;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.util.GOSTUtils;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import javax.crypto.Cipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CipherWrapper {

    private static final Logger LOGGER = LogManager.getLogger();

    public static EncryptionCipher getEncryptionCipher(CipherSuite cipherSuite, ConnectionEndType connectionEndType,
        KeySet keySet) {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
        if (cipherAlg == CipherAlgorithm.GOST_28147_CNT) {
            return new GOST28147Cipher(GOSTUtils.getGostSpec(cipherSuite), keySet.getWriteKey(connectionEndType),
                keySet.getWriteIv(connectionEndType));
        } else if (cipherAlg == CipherAlgorithm.CHACHA20_POLY1305) {
            return new StandardizedChaCha20Poly1305Cipher(keySet.getWriteKey(connectionEndType));
        } else if (cipherAlg == CipherAlgorithm.UNOFFICIAL_CHACHA20_POLY1305) {
            return new UnofficialChaCha20Poly1305Cipher(keySet.getWriteKey(connectionEndType));
        } else if (cipherAlg.getJavaName() != null) {
            return new JavaCipher(cipherAlg, keySet.getWriteKey(connectionEndType),
                AlgorithmResolver.getCipherType(cipherSuite) == CipherType.STREAM);
        } else if (cipherAlg == CipherAlgorithm.NULL) {
            return new NullCipher();
        } else {
            LOGGER.warn("Cipher:" + cipherAlg + " is not supported - Using NullCipher!");
            return new NullCipher();
        }
    }

    public static DecryptionCipher getDecryptionCipher(CipherSuite cipherSuite, ConnectionEndType connectionEndType,
        KeySet keySet) {
        CipherAlgorithm cipherAlg = AlgorithmResolver.getCipher(cipherSuite);
        if (cipherAlg == CipherAlgorithm.GOST_28147_CNT) {
            return new GOST28147Cipher(GOSTUtils.getGostSpec(cipherSuite), keySet.getReadKey(connectionEndType),
                keySet.getReadIv(connectionEndType));
        } else if (cipherAlg == CipherAlgorithm.CHACHA20_POLY1305) {
            return new StandardizedChaCha20Poly1305Cipher(keySet.getReadKey(connectionEndType));
        } else if (cipherAlg == CipherAlgorithm.UNOFFICIAL_CHACHA20_POLY1305) {
            return new UnofficialChaCha20Poly1305Cipher(keySet.getReadKey(connectionEndType));
        } else if (cipherAlg.getJavaName() != null) {
            return new JavaCipher(cipherAlg, keySet.getReadKey(connectionEndType),
                AlgorithmResolver.getCipherType(cipherSuite) == CipherType.STREAM);
        } else if (cipherAlg == CipherAlgorithm.NULL) {
            return new NullCipher();
        } else {
            LOGGER.warn("Cipher:" + cipherAlg + " is not supported - Using NullCipher!");
            return new NullCipher();
        }
    }

    private CipherWrapper() {
    }

}
