/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class MathHelperTest {

    /** Test of intfloordiv method, of class MathHelper. */
    @Test
    @Disabled("Not implemented")
    public void testIntfloordiv_BigInteger_BigInteger() {}

    /** Test of intceildiv method, of class MathHelper. */
    @Test
    @Disabled("Not implemented")
    public void testIntceildiv_BigInteger_BigInteger() {}

    /** Test of intfloordiv method, of class MathHelper. */
    @Test
    @Disabled("Not implemented")
    public void testIntfloordiv_int_int() {}

    /** Test of intceildiv method, of class MathHelper. */
    @Test
    @Disabled("Not implemented")
    public void testIntceildiv_int_int() {}

    /** Test of extendedEuclid method, of class MathHelper. */
    @Test
    @Disabled("Not implemented")
    public void testExtendedEuclid() {}

    /** Test of gcd method, of class MathHelper. */
    @Test
    @Disabled("Not implemented")
    public void testGcd() {}

    /** Test of inverseMod method, of class MathHelper. */
    @Test
    @Disabled("Not implemented")
    public void testInverseMod() {}

    /** Test of CRT method, of class MathHelper. */
    @Test
    public void testCRT() {
        BigInteger[] congs = {new BigInteger("3"), new BigInteger("4"), new BigInteger("5")};
        BigInteger[] moduli = {new BigInteger("2"), new BigInteger("3"), new BigInteger("2")};
        assertEquals(4, MathHelper.crt(congs, moduli).intValue());

        // computes:
        // x == 2 mod 3
        // x == 3 mod 4
        // x == 1 mod 5
        BigInteger[] congs2 = {new BigInteger("2"), new BigInteger("3"), new BigInteger("1")};
        BigInteger[] moduli2 = {new BigInteger("3"), new BigInteger("4"), new BigInteger("5")};
        assertEquals(11, MathHelper.crt(congs2, moduli2).intValue());
    }
}
