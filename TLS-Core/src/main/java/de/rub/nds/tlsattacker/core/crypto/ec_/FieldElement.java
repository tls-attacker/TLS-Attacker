/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.tlsattacker.core.crypto.ec_;

import java.math.BigInteger;

/**
 * Can be used to store elements of a galois field.<br />
 * The attribute data should contain some BigInteger representing the element.<br />
 * The attribute modulus should contain some BigInteger that may be used to
 * identify the field (and for calculations).<br />
 * 
 * All arithmetic operations are performed within the laws of the specified
 * field.
 */
public abstract class FieldElement {
    /*
     * FieldElement objects are immutable. This should make deep copies in the
     * methods of the EllipticCurve class unnecessary.
     */
    private final BigInteger data;
    private final BigInteger modulus;

    public FieldElement(BigInteger data, BigInteger modulus) {
        this.data = data;
        this.modulus = modulus;
    }

    /**
     * Returns this + f.
     * 
     * @param f
     *            An element of the field, which this is an element of.
     */

    public abstract FieldElement add(FieldElement f);

    /**
     * Returns this - f. <br />
     * 
     * @param f
     *            An element of the field, which this is an element of.
     */
    public FieldElement subtract(FieldElement f) {
        f = f.addInv();
        return add(f);
    }

    /**
     * Returns this * f.<br />
     * 
     * @param f
     *            An element of the field, which this is an element of.
     */
    public abstract FieldElement mult(FieldElement f);

    /**
     * Returns this * f^-1.<br />
     * 
     * @param f
     *            An element of the field, which this is an element of.
     */
    public FieldElement divide(FieldElement f) {
        f = f.multInv();
        return mult(f);
    }

    /**
     * Returns -this.
     */
    public abstract FieldElement addInv();

    /**
     * Returns this^-1.
     */
    public abstract FieldElement multInv();

    public BigInteger getData() {
        return this.data;
    }

    public BigInteger getModulus() {
        return this.modulus;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || this.getClass() != obj.getClass()) {
            return false;
        } else {
            FieldElement f = (FieldElement) obj;
            return this.getData().equals(f.getData()) && this.getModulus().equals(f.getModulus());
        }
    }

    @Override
    public String toString() {
        return this.getData().toString() + " mod " + this.getModulus().toString();
    }

}
