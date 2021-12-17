/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 * <p>
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto.ffdh;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class FFDHEGroupTest {

    @Before
    public void setUp() {
    }

    @Test
    public void test() {
        int counter = 0;
        int implemented = 5;
        for (NamedGroup name : NamedGroup.values()) {
            try {
                FFDHEGroup group = GroupFactory.getGroup(name);
                BigInteger p = group.getP();
                BigInteger g = group.getG();

                assertTrue(p.isProbablePrime(32));
                BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
                assertTrue(q.isProbablePrime(32));
                assertEquals(BigInteger.ONE, g.modPow(q, p));

                counter++;
            } catch (UnsupportedOperationException e) {
            }
        }
        assertEquals(implemented, counter);
    }
}
