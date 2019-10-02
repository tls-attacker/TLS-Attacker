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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * An element of a galois field F_{2^m}.<br />
 * Please notice that every element in the field (and the redcution polynomial
 * that defines the field) is represented by a binary polynomial.<br />
 * These polynomials are represented by BigInteger bit-strings, where the i-th
 * bit represents the i-th coefficient.
 */
public class FieldElementF2m extends FieldElement implements Serializable {

    private final static Logger LOGGER = LogManager.getLogger();

    /**
     * Instantiates an element of a galois field F{2^m}.
     *
     * @param data
     *            The binary polynomial representing the element.<br />
     *            The degree must be smaller than the reduction polynomial's
     *            degree.
     * @param modulus
     *            The binary reduction polynomial defining the field.
     */
    public FieldElementF2m(BigInteger data, BigInteger modulus) {
        super(data, modulus);
    }

    private FieldElementF2m() {
        super(null, null);
    }

    @Override
    public FieldElement add(FieldElement f) {
        // Coefficients are added mod 2.
        BigInteger tmp = this.getData().xor(f.getData());
        return new FieldElementF2m(tmp, this.getModulus());
    }

    @Override
    public FieldElement mult(FieldElement f) {
        // Binary polynomial school book multiplication.

        BigInteger thisData = this.getData();
        BigInteger fData = f.getData();
        BigInteger tmp = new BigInteger("0");

        for (int i = 0; i < fData.bitLength(); i++) {
            if (fData.testBit(i)) {
                tmp = tmp.xor(thisData.shiftLeft(i));
            }
        }

        tmp = this.reduce(tmp);
        return new FieldElementF2m(tmp, this.getModulus());
    }

    @Override
    public FieldElement addInv() {
        /*
         * The characteristic of F_{2^m} is 2. Therefore every element is it's
         * own additive inverse. Like this.subtract(), this method is probably
         * never needed.
         */
        return this;
    }

    @Override
    public FieldElement multInv() {
        if (this.getData().equals(BigInteger.ZERO)) {
            throw new ArithmeticException();
        }

        if (this.getData().equals(BigInteger.ONE)) {
            return this;
        }

        // Polynomial EEA:
        BigInteger r2 = this.getModulus();
        BigInteger r1 = this.getData();
        BigInteger t2 = new BigInteger("0");
        BigInteger t1 = BigInteger.ONE;

        do {
            BigInteger[] division = this.polynomialDivision(r2, r1);
            // r = r2 mod r1
            BigInteger r = division[1];
            // q = (r2 - r) / r1
            BigInteger q = division[0];

            // t = t2 - (t1 * q)
            FieldElementF2m t1Polynomial = new FieldElementF2m(t1, this.getModulus());
            FieldElementF2m qPolynomial = new FieldElementF2m(q, this.getModulus());

            BigInteger t = t1Polynomial.mult(qPolynomial).getData();
            t = this.reduce(t);
            t = t2.xor(t);

            t2 = t1;
            t1 = t;
            r2 = r1;
            r1 = r;

        } while (!r1.equals(BigInteger.ONE) && !r1.equals(BigInteger.ZERO));

        // t1 * this.getData() == 1
        return new FieldElementF2m(t1, this.getModulus());
    }

    /**
     * Polynomial division f/p.<br />
     * Returns an BigInteger array representing the polynomials q and r with: <br />
     * q * p + r = f.
     *
     * @param f
     *            A BigInteger representing a binary polynomial.
     * @param p
     *            A BigInteger representing a binary polynomial.
     *
     */
    private BigInteger[] polynomialDivision(BigInteger f, BigInteger p) {
        int modLength = p.bitLength();
        BigInteger q = new BigInteger("0");
        while (f.bitLength() >= modLength && modLength != 0) {
            BigInteger tmp = new BigInteger("1");
            tmp = tmp.shiftLeft(f.bitLength() - modLength);
            q = q.xor(tmp);

            BigInteger shift = p.multiply(tmp);
            f = f.xor(shift);
        }
        // q is the quotient.
        // f is the remainder.
        BigInteger[] result = { q, f };
        return result;
    }

    /**
     * Returns f mod this.getModulus().
     *
     * @param f
     *            A BigInteger representing a binary polynomial.
     */
    private BigInteger reduce(BigInteger f) {
        return this.polynomialDivision(f, this.getModulus())[1];
    }
}
