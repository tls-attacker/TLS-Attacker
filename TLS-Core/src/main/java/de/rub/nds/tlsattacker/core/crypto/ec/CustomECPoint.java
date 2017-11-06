/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;


public class CustomECPoint implements Serializable {

    private BigInteger x;

    private BigInteger y;

    public CustomECPoint() {
    }

    public CustomECPoint(CustomECPoint other) {
        x = other.x;
        y = other.y;
    }

    public CustomECPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public BigInteger getX() {
        return x;
    }

    public void setX(BigInteger x) {
        this.x = x;
    }

    public byte[] getByteX() {
        return toUnsignedByteArray(x);
    }

    public byte[] getByteY() {
        return toUnsignedByteArray(y);
    }

    public BigInteger getY() {
        return y;
    }

    public void setY(BigInteger y) {
        this.y = y;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 79 * hash + Objects.hashCode(this.x);
        hash = 79 * hash + Objects.hashCode(this.y);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CustomECPoint other = (CustomECPoint) obj;
        if (!Objects.equals(this.x, other.x)) {
            return false;
        }
        if (!Objects.equals(this.y, other.y)) {
            return false;
        }
        return true;
    }

    public static byte[] toUnsignedByteArray(BigInteger value) {
        byte[] signedValue = value.toByteArray();
        if (signedValue[0] != 0x00) {
            return value.toByteArray();
        }
        return Arrays.copyOfRange(signedValue, 1, signedValue.length);
    }

    public static BigInteger fromUnsignedByteArray(byte[] value) {
        byte[] signedValue = new byte[value.length + 1];
        System.arraycopy(value, 0, signedValue, 1, value.length);
        return new BigInteger(signedValue);
    }
}
