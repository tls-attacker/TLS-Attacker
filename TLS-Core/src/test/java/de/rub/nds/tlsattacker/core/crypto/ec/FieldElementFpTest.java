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

public class FieldElementFpTest {

    private BigInteger modulus;
    private FieldElementFp e1;
    private FieldElementFp e2;
    private FieldElementFp e3;
    private FieldElementFp e4;
    private FieldElementFp zero;

    @Before
    public void setUp() {
        modulus = new BigInteger("113");
        e1 = new FieldElementFp(new BigInteger("57"), modulus);
        e2 = new FieldElementFp(new BigInteger("24"), modulus);
        e3 = new FieldElementFp(new BigInteger("81"), modulus);
        e4 = new FieldElementFp(new BigInteger("3"), modulus);
        zero = new FieldElementFp(BigInteger.ZERO, modulus);
    }

    @Test
    public void testAdd() {
        // Addition without reduction
        FieldElementFp tmp = (FieldElementFp) e1.add(e2);
        FieldElementFp result = new FieldElementFp(new BigInteger("81"), modulus);
        assertEquals(result, tmp);

        // Addition with reduction
        tmp = (FieldElementFp) e1.add(e3);
        result = new FieldElementFp(new BigInteger("25"), modulus);
        assertEquals(result, tmp);
        result = new FieldElementFp(new BigInteger("138"), modulus);
        assertEquals(result, tmp);
    }

    @Test
    public void testSubtract() {
        // Subtraction without reduction
        FieldElementFp tmp = (FieldElementFp) e1.subtract(e2);
        FieldElementFp result = new FieldElementFp(new BigInteger("33"), modulus);
        assertEquals(result, tmp);

        // Subtraction with reduction
        tmp = (FieldElementFp) e2.subtract(e1);
        result = new FieldElementFp(new BigInteger("80"), modulus);
        assertEquals(result, tmp);
        result = new FieldElementFp(new BigInteger("-33"), modulus);
        assertEquals(result, tmp);
    }

    @Test
    public void testMult() {
        // Multiplication without reduction
        FieldElementFp tmp = (FieldElementFp) e2.mult(e4);
        FieldElementFp result = new FieldElementFp(new BigInteger("72"), modulus);
        assertEquals(result, tmp);

        // Multiplication with reduction
        tmp = (FieldElementFp) e1.mult(e2);
        result = new FieldElementFp(new BigInteger("12"), modulus);
        assertEquals(result, tmp);
        result = new FieldElementFp(new BigInteger("1368"), modulus);
        assertEquals(result, tmp);
    }

    @Test
    public void testDivide() {
        // Division without reduction
        FieldElementFp tmp = (FieldElementFp) e2.divide(e1);
        FieldElementFp result = new FieldElementFp(new BigInteger("48"), modulus);
        assertEquals(result, tmp);

        // Division with reduction
        tmp = (FieldElementFp) e1.divide(e2);
        result = new FieldElementFp(new BigInteger("73"), modulus);
        assertEquals(result, tmp);
        result = new FieldElementFp(new BigInteger("1881"), modulus);
        assertEquals(result, tmp);

        try {
            e1.divide(zero);
            fail();
        } catch (ArithmeticException e) {
        }
    }

    @Test
    public void testAddInv() {
        FieldElementFp tmp = (FieldElementFp) e1.addInv();
        FieldElementFp result = new FieldElementFp(new BigInteger("56"), modulus);
        assertEquals(result, tmp);
    }

    @Test
    public void testMultInv() {
        FieldElementFp tmp = (FieldElementFp) e2.multInv();
        FieldElementFp result = new FieldElementFp(new BigInteger("33"), modulus);
        assertEquals(result, tmp);

        try {
            zero.multInv();
            fail();
        } catch (ArithmeticException e) {
        }
    }

    @Test
    public void testEquals() {
        assertNotEquals(e1, e2);
        assertEquals(e1, e1);

        BigInteger e1Data = e1.getData();

        FieldElementFp e1_ = new FieldElementFp(e1Data, modulus);
        assertEquals(e1, e1_);
        e1_ = new FieldElementFp(e1Data, modulus.add(BigInteger.ONE));
        assertNotEquals(e1, e1_);
        e1_ = new FieldElementFp(e1Data.add(BigInteger.ONE), modulus);
        assertNotEquals(e1, e1_);
        e1_ = new FieldElementFp(e1Data.add(BigInteger.ONE), modulus.add(BigInteger.ONE));
        assertNotEquals(e1, e1_);
    }

}
