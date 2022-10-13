/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.crypto;

import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * Merget <robert.merget@rub.de>
 */
public class KeyShareCalculatorTest {

    public KeyShareCalculatorTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Test of createClassicEcPublicKey method, of class KeyShareCalculator.
     */
    @Test
    public void testCreateClassicEcPublicKey() {
    }

    /**
     * Test of createX25519KeyShare method, of class KeyShareCalculator.
     */
    @Test
    public void testCreateX25519KeyShare() {
    }

    @Test
    public void crashTest() {
        List<BigInteger> somePrivateKeyList = new LinkedList<>();
        somePrivateKeyList.add(BigInteger.ZERO);
        somePrivateKeyList.add(BigInteger.ONE);
        somePrivateKeyList.add(new BigInteger(8, new Random(0)));
        somePrivateKeyList.add(new BigInteger(32, new Random(0)));
        somePrivateKeyList.add(new BigInteger(128, new Random(0)));
        somePrivateKeyList.add(new BigInteger(256, new Random(0)));
        for (BigInteger bigInt : somePrivateKeyList) {
            for (NamedGroup group : NamedGroup.getImplemented()) {
                KeyShareCalculator.createPublicKey(group, bigInt, ECPointFormat.UNCOMPRESSED);
            }

            for (NamedGroup greaseGroup : Arrays.asList(NamedGroup.values()).stream().filter(NamedGroup::isGrease)
                .collect(Collectors.toList())) {
                KeyShareCalculator.createPublicKey(greaseGroup, bigInt, ECPointFormat.UNCOMPRESSED);
            }
        }
    }
}
