/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.crypto.ec;

import java.math.BigInteger;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;

public class FieldElementF2mTest {

    private BigInteger modulus;
    private FieldElementF2m p1;
    private FieldElementF2m p2;
    private FieldElementF2m neutral;
    private FieldElementF2m p4;
    private FieldElementF2m p5;
    private FieldElementF2m zero;

    @Before
    public void setUp() {
        /*
         * x^3 + x + 1 has no roots over F_2 and it's degree is less than 4.
         * This implies that it is irreducible over F_2[x].
         */
        modulus = new BigInteger("1011", 2);
        p1 = new FieldElementF2m(new BigInteger("101", 2), modulus);
        p2 = new FieldElementF2m(new BigInteger("111", 2), modulus);
        neutral = new FieldElementF2m(BigInteger.ONE, modulus);
        p4 = new FieldElementF2m(new BigInteger("10", 2), modulus);
        p5 = new FieldElementF2m(new BigInteger("11", 2), modulus);
        zero = new FieldElementF2m(BigInteger.ZERO, modulus);
    }

    @Test
    public void testAdd() {
        FieldElementF2m tmp = (FieldElementF2m) p1.add(p2);
        FieldElementF2m result = new FieldElementF2m(new BigInteger("10", 2), modulus);
        assertEquals(result, tmp);
    }

    @Test
    public void testSubtract() {
        FieldElementF2m tmp = (FieldElementF2m) p1.subtract(p2);
        FieldElementF2m result = new FieldElementF2m(new BigInteger("10", 2), modulus);
        assertEquals(result, tmp);
    }

    @Test
    public void testMult() {
        FieldElementF2m tmp = (FieldElementF2m) p1.mult(neutral);
        assertEquals(p1, tmp);

        // Multiplication with reduction
        tmp = (FieldElementF2m) p1.mult(p2);
        FieldElementF2m result = new FieldElementF2m(new BigInteger("110", 2), modulus);
        assertEquals(result, tmp);

        tmp = (FieldElementF2m) p1.mult(p1.multInv());
        assertEquals(neutral, tmp);

        // Multiplication without reduction
        tmp = (FieldElementF2m) p4.mult(p5);
        assertEquals(result, tmp);
    }

    @Test
    public void testDivide() {
        FieldElementF2m tmp = (FieldElementF2m) p1.divide(p1);
        assertEquals(neutral, tmp);

        tmp = (FieldElementF2m) p2.divide(p2);
        assertEquals(neutral, tmp);

        tmp = (FieldElementF2m) neutral.divide(neutral);
        assertEquals(neutral, tmp);

        tmp = (FieldElementF2m) p2.divide(p1);
        FieldElementF2m result = new FieldElementF2m(new BigInteger("101", 2), modulus);
        assertEquals(result, tmp);

        try {
            p4.divide(zero);
            fail();
        } catch (ArithmeticException e) {
        }
    }

    @Test
    public void testAddInv() {
        FieldElementF2m tmp = (FieldElementF2m) p4.addInv();
        assertEquals(p4, tmp);
    }

    @Test
    public void testMultInv() {
        FieldElementF2m tmp = (FieldElementF2m) neutral.multInv();
        assertEquals(neutral, tmp);

        tmp = (FieldElementF2m) p1.multInv();
        FieldElementF2m result = new FieldElementF2m(new BigInteger("10", 2), modulus);
        assertEquals(result, tmp);

        tmp = (FieldElementF2m) p5.multInv();
        result = new FieldElementF2m(new BigInteger("110", 2), modulus);
        assertEquals(result, tmp);

        try {
            zero.multInv();
            fail();
        } catch (ArithmeticException e) {
        }
    }

    @Test
    public void testEquals() {
        assertNotEquals(p1, p2);
        assertEquals(p1, p1);

        BigInteger p1Data = p1.getData();

        FieldElementF2m p1_ = new FieldElementF2m(p1Data, modulus);
        assertEquals(p1, p1_);
        p1_ = new FieldElementF2m(p1Data, modulus.add(BigInteger.ONE));
        assertNotEquals(p1, p1_);
        p1_ = new FieldElementF2m(p1Data.add(BigInteger.ONE), modulus);
        assertNotEquals(p1, p1_);
        p1_ = new FieldElementF2m(p1Data.add(BigInteger.ONE), modulus.add(BigInteger.ONE));
        assertNotEquals(p1, p1_);
    }

}
