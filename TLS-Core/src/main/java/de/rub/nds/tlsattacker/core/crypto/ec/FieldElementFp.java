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

/**
 * An element of the field F_p (with p being a prime number).
 */
public class FieldElementFp extends FieldElement implements Serializable {

    /**
     * Instantiates the element data in the field F_modulus. With modulus being
     * a prime number.
     */
    public FieldElementFp(BigInteger data, BigInteger modulus) {
        super(data.mod(modulus), modulus);
    }

    private FieldElementFp() {
        super(null, null);
    }

    @Override
    public FieldElement add(FieldElement f) {
        BigInteger tmp = this.getData().add(f.getData());
        tmp = tmp.mod(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }

    @Override
    public FieldElement mult(FieldElement f) {
        BigInteger tmp = this.getData().multiply(f.getData());
        tmp = tmp.mod(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }

    @Override
    public FieldElement addInv() {
        BigInteger tmp = this.getData().negate();
        tmp = tmp.mod(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }

    @Override
    public FieldElement multInv() {
        if (this.getData().equals(BigInteger.ZERO)) {
            throw new ArithmeticException();
        }
        BigInteger tmp = this.getData().modInverse(this.getModulus());
        return new FieldElementFp(tmp, this.getModulus());
    }
}
