/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import de.rub.nds.protocol.crypto.kem.MlKemEncapsulation;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class KeyShareCalculatorTest {

    /** Test of createClassicEcPublicKey method, of class KeyShareCalculator. */
    @Test
    @Disabled("Not implemented")
    public void testCreateClassicEcPublicKey() {}

    /** Test of createX25519KeyShare method, of class KeyShareCalculator. */
    @Test
    @Disabled("Not implemented")
    public void testCreateX25519KeyShare() {}

    @Test
    @Tag(TestCategories.SLOW_TEST)
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
                KeyShareCalculator.createKeyAgreementPublicKey(
                        group, bigInt, ECPointFormat.UNCOMPRESSED);
            }

            for (NamedGroup greaseGroup :
                    Arrays.stream(NamedGroup.values())
                            .filter(NamedGroup::isGrease)
                            .collect(Collectors.toList())) {
                KeyShareCalculator.createKeyAgreementPublicKey(
                        greaseGroup, bigInt, ECPointFormat.UNCOMPRESSED);
            }
        }
    }

    @Test
    public void testMLKEMEncapsDecaps() {
        NamedGroup group = NamedGroup.MLKEM512;
        KeyShareEntry clientEntry = new KeyShareEntry();
        KeyShareCalculator.createMLKEMKeyShare(group, clientEntry, new SecureRandom());

        MlKemEncapsulation encapsulationResult =
                KeyShareCalculator.mlkemEncaps(
                        group, clientEntry.getMLKEMPublicKey().getValue(), new SecureRandom());

        assertNotNull(encapsulationResult.getSharedSecret());
        assertNotNull(encapsulationResult.getCiphertext());

        byte[] decapsulatedSecret =
                KeyShareCalculator.mlkemDecaps(
                        group,
                        clientEntry.getMLKEMPrivateKeyContainer(),
                        encapsulationResult.getCiphertext());

        assertArrayEquals(encapsulationResult.getSharedSecret(), decapsulatedSecret);
    }
}
