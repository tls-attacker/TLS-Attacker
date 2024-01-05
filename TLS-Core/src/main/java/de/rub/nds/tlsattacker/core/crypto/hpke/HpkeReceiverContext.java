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
import de.rub.nds.tlsattacker.core.crypto.cipher.DecryptionCipher;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class HpkeReceiverContext extends HpkeContext {

    public HpkeReceiverContext(
            byte[] aeadKey,
            byte[] baseNonce,
            int sequenceNumber,
            byte[] exporterSecret,
            HpkeAeadFunction hpkeAeadFunction) {
        super(aeadKey, baseNonce, sequenceNumber, exporterSecret, hpkeAeadFunction);
    }

    public byte[] open(byte[] additionalAuthenticatedData, byte[] ciphertext, byte[] nonce)
            throws CryptoException {
        KeySet keySet = new KeySet();
        keySet.setClientWriteKey(aeadKey);
        DecryptionCipher decryptionCipher =
                CipherWrapper.getDecryptionCipher(
                        hpkeAeadFunction.getCipherSuite(), ConnectionEndType.SERVER, keySet);
        byte[] plaintext =
                decryptionCipher.decrypt(
                        nonce,
                        hpkeAeadFunction.getTagLength() * 8,
                        additionalAuthenticatedData,
                        ciphertext);
        this.incrementSequenceNumber();
        return plaintext;
    }

    public byte[] open(byte[] additionalAuthenticatedData, byte[] plaintext)
            throws CryptoException {
        return open(additionalAuthenticatedData, plaintext, computeNonce());
    }
}
