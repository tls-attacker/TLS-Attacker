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
import org.junit.Test;

public class PointTest {

    @Test
    public void testEquals() {
        BigInteger i1 = new BigInteger("12345678");
        BigInteger i2 = new BigInteger("23456789");
        BigInteger i3 = new BigInteger("34567891");
        BigInteger i4 = new BigInteger("45678912");
        BigInteger mod1 = new BigInteger("111111122222");
        BigInteger mod2 = new BigInteger("121212121212");

        FieldElementFp f1 = new FieldElementFp(i1, mod1);
        FieldElementFp f2 = new FieldElementFp(i2, mod1);
        FieldElementFp f3 = new FieldElementFp(i3, mod1);
        FieldElementFp f4 = new FieldElementFp(i4, mod1);
        FieldElementFp f1_ = new FieldElementFp(i1, mod2);
        FieldElementFp f2_ = new FieldElementFp(i2, mod2);

        Point p1 = new Point(f1, f2);
        Point p2 = new Point(f3, f4);
        Point p1_ = new Point(f1_, f2_);

        assertEquals(p1, p1);
        assertEquals(p2, p2);
        assertEquals(p1_, p1_);
        assertNotEquals(p1, p2);
        assertNotEquals(p1, p1_);
    }

}
