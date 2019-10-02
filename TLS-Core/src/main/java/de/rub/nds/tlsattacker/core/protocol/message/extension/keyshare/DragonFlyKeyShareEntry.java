/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare;

import java.math.BigInteger;

public class DragonFlyKeyShareEntry {

    private byte[] rawPublicKey;

    private int scalarLength;

    private BigInteger scalar;

    public DragonFlyKeyShareEntry(byte[] rawPublicKey, int scalarLength, BigInteger scalar) {
        this.rawPublicKey = rawPublicKey;
        this.scalarLength = scalarLength;
        this.scalar = scalar;
    }

    public byte[] getRawPublicKey() {
        return rawPublicKey;
    }

    public void setRawPublicKey(byte[] rawPublicKey) {
        this.rawPublicKey = rawPublicKey;
    }

    public int getScalarLength() {
        return scalarLength;
    }

    public void setScalarLength(int scalarLength) {
        this.scalarLength = scalarLength;
    }

    public BigInteger getScalar() {
        return scalar;
    }

    public void setScalar(BigInteger scalar) {
        this.scalar = scalar;
    }
}
