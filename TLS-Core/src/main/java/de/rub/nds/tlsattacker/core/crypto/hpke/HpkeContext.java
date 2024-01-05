/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.hpke;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;

public abstract class HpkeContext {

    protected final byte[] aeadKey;

    protected final byte[] baseNonce;

    protected final byte[] exporterSecret;

    protected final HpkeAeadFunction hpkeAeadFunction;

    protected int sequenceNumber;

    public HpkeContext(
            byte[] aeadKey,
            byte[] baseNonce,
            int sequenceNumber,
            byte[] exporterSecret,
            HpkeAeadFunction hpkeAeadFunction) {
        this.aeadKey = aeadKey;
        this.baseNonce = baseNonce;
        this.exporterSecret = exporterSecret;
        this.sequenceNumber = sequenceNumber;
        this.hpkeAeadFunction = hpkeAeadFunction;
    }

    protected byte[] computeNonce() {
        // base_nonce ^ seq_number
        byte[] sequenceBytes =
                ArrayConverter.intToBytes(sequenceNumber, hpkeAeadFunction.getNonceLength());
        byte[] nonce = new byte[sequenceBytes.length];
        for (int i = 0; i < sequenceBytes.length; i++) {
            nonce[i] = (byte) (sequenceBytes[i] ^ baseNonce[i]);
        }
        return nonce;
    }

    protected void incrementSequenceNumber() throws CryptoException {
        if (Integer.bitCount(sequenceNumber) >= (8 * hpkeAeadFunction.getNonceLength())) {
            throw new CryptoException("Message limit reached");
        }
    }
}
