/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.hpke;

import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.crypto.cipher.CipherWrapper;
import de.rub.nds.tlsattacker.core.crypto.cipher.EncryptionCipher;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class HpkeSenderContext extends HpkeContext {

    public HpkeSenderContext(
            byte[] aeadKey,
            byte[] baseNonce,
            int sequenceNumber,
            byte[] exporterSecret,
            HpkeAeadFunction hpkeAeadFunction) {
        super(aeadKey, baseNonce, sequenceNumber, exporterSecret, hpkeAeadFunction);
    }

    /** Encrypts the given plaintext using the provided nonce, aad and already provided key. */
    public byte[] seal(byte[] additionalAuthenticatedData, byte[] plaintext, byte[] nonce)
            throws CryptoException {
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(aeadKey);
        EncryptionCipher encryptionCipher =
                CipherWrapper.getEncryptionCipher(
                        hpkeAeadFunction.getCipherSuite(), ConnectionEndType.CLIENT, keySet);
        byte[] ciphertext =
                encryptionCipher.encrypt(
                        nonce,
                        hpkeAeadFunction.getTagLength() * 8,
                        additionalAuthenticatedData,
                        plaintext);
        this.incrementSequenceNumber();
        return ciphertext;
    }

    public byte[] seal(byte[] additionalAuthenticatedData, byte[] plaintext)
            throws CryptoException {
        return seal(additionalAuthenticatedData, plaintext, computeNonce());
    }
}
