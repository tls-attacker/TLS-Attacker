/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto.pq;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.SecureRandom;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class PQUtilsTest {

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testSplitClientKeyShare(NamedGroup namedGroup) {
        SecureRandom secureRandom = new SecureRandom();
        ConnectionEndType connectionEndType = ConnectionEndType.CLIENT;

        int classicalKeyShareLength = PQUtils.getClassicalKeyShareLength(namedGroup);
        int pqKeyShareLength = PQUtils.getPQKeyShareLength(namedGroup, connectionEndType);

        byte[] classicalKeyShare = new byte[classicalKeyShareLength];
        byte[] pqKeyShare = new byte[pqKeyShareLength];

        secureRandom.nextBytes(classicalKeyShare);
        secureRandom.nextBytes(pqKeyShare);

        byte[] keyShare;
        if (namedGroup.equals(NamedGroup.X25519_MLKEM768)) {
            keyShare = DataConverter.concatenate(pqKeyShare, classicalKeyShare);
        } else {
            keyShare = DataConverter.concatenate(classicalKeyShare, pqKeyShare);
        }

        byte[][] splitKeyShare = PQUtils.splitKeyShare(namedGroup, connectionEndType, keyShare);
        assertArrayEquals(classicalKeyShare, splitKeyShare[0]);
        assertArrayEquals(pqKeyShare, splitKeyShare[1]);
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testSplitServerKeyShare(NamedGroup namedGroup) {
        SecureRandom secureRandom = new SecureRandom();
        ConnectionEndType connectionEndType = ConnectionEndType.SERVER;

        int classicalKeyShareLength = PQUtils.getClassicalKeyShareLength(namedGroup);
        int pqKeyShareLength = PQUtils.getPQKeyShareLength(namedGroup, connectionEndType);

        byte[] classicalKeyShare = new byte[classicalKeyShareLength];
        byte[] pqKeyShare = new byte[pqKeyShareLength];

        secureRandom.nextBytes(classicalKeyShare);
        secureRandom.nextBytes(pqKeyShare);

        byte[] keyShare;
        if (namedGroup.equals(NamedGroup.X25519_MLKEM768)) {
            keyShare = DataConverter.concatenate(pqKeyShare, classicalKeyShare);
        } else {
            keyShare = DataConverter.concatenate(classicalKeyShare, pqKeyShare);
        }

        byte[][] splitKeyShare = PQUtils.splitKeyShare(namedGroup, connectionEndType, keyShare);
        assertArrayEquals(classicalKeyShare, splitKeyShare[0]);
        assertArrayEquals(pqKeyShare, splitKeyShare[1]);
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testConcatenateKeyShare(NamedGroup namedGroup) {
        SecureRandom secureRandom = new SecureRandom();

        int classicalKeyShareLength = PQUtils.getClassicalKeyShareLength(namedGroup);
        int pqKeyShareLength = PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.CLIENT);

        byte[] classicalKeyShare = new byte[classicalKeyShareLength];
        byte[] pqKeyShare = new byte[pqKeyShareLength];

        secureRandom.nextBytes(classicalKeyShare);
        secureRandom.nextBytes(pqKeyShare);

        byte[] concatenatedHybridKeyShare =
                PQUtils.concatenateHybridKeyShare(namedGroup, classicalKeyShare, pqKeyShare, true);

        if (namedGroup.equals(NamedGroup.X25519_MLKEM768)) {
            assertArrayEquals(
                    pqKeyShare,
                    Arrays.copyOfRange(concatenatedHybridKeyShare, 0, pqKeyShareLength));
            assertArrayEquals(
                    classicalKeyShare,
                    Arrays.copyOfRange(
                            concatenatedHybridKeyShare,
                            pqKeyShareLength,
                            concatenatedHybridKeyShare.length));
        } else {
            assertArrayEquals(
                    classicalKeyShare,
                    Arrays.copyOfRange(concatenatedHybridKeyShare, 0, classicalKeyShareLength));
            assertArrayEquals(
                    pqKeyShare,
                    Arrays.copyOfRange(
                            concatenatedHybridKeyShare,
                            classicalKeyShareLength,
                            concatenatedHybridKeyShare.length));
        }

        byte[] reverseConcatenatedHybridKeyShare =
                PQUtils.concatenateHybridKeyShare(namedGroup, classicalKeyShare, pqKeyShare, false);

        if (namedGroup.equals(NamedGroup.X25519_MLKEM768)) {
            assertArrayEquals(
                    classicalKeyShare,
                    Arrays.copyOfRange(
                            reverseConcatenatedHybridKeyShare, 0, classicalKeyShareLength));
            assertArrayEquals(
                    pqKeyShare,
                    Arrays.copyOfRange(
                            reverseConcatenatedHybridKeyShare,
                            classicalKeyShareLength,
                            reverseConcatenatedHybridKeyShare.length));
        } else {
            assertArrayEquals(
                    pqKeyShare,
                    Arrays.copyOfRange(reverseConcatenatedHybridKeyShare, 0, pqKeyShareLength));
            assertArrayEquals(
                    classicalKeyShare,
                    Arrays.copyOfRange(
                            reverseConcatenatedHybridKeyShare,
                            pqKeyShareLength,
                            reverseConcatenatedHybridKeyShare.length));
        }
    }
}
