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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.constants.MlKemParameters;
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

        int classicalKeyShareLength = PQUtils.getEcPublicKeyLength(namedGroup);
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

        int classicalKeyShareLength = PQUtils.getEcPublicKeyLength(namedGroup);
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

        int classicalKeyShareLength = PQUtils.getEcPublicKeyLength(namedGroup);
        int pqKeyShareLength = PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.CLIENT);

        byte[] classicalKeyShare = new byte[classicalKeyShareLength];
        byte[] pqKeyShare = new byte[pqKeyShareLength];

        secureRandom.nextBytes(classicalKeyShare);
        secureRandom.nextBytes(pqKeyShare);

        byte[] concatenatedHybridKeyShare =
                PQUtils.concatenateHybridKeyShare(namedGroup, classicalKeyShare, pqKeyShare);

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
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"ECDH_X25519", "SECP256R1", "FFDHE2048"})
    public void testGetPQKeyShareLengthRejectsNonPqGroup(NamedGroup namedGroup) {
        assertThrows(
                UnsupportedOperationException.class,
                () -> PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.CLIENT));
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM512", "MLKEM768", "MLKEM1024"})
    public void testGetPQKeyShareLengthAcceptsPureMlKemGroup(NamedGroup namedGroup) {
        assertEquals(
                ((MlKemParameters) namedGroup.getAsymmetricParameters())
                        .getEncapsulationKeySizeBytes(),
                PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.CLIENT));
        assertEquals(
                ((MlKemParameters) namedGroup.getAsymmetricParameters()).getCiphertextSizeBytes(),
                PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.SERVER));
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM768", "ECDH_X25519", "FFDHE2048"})
    public void testGetEcPublicKeyLengthRejectsNonHybridGroup(NamedGroup namedGroup) {
        assertThrows(
                UnsupportedOperationException.class,
                () -> PQUtils.getEcPublicKeyLength(namedGroup));
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM768", "ECDH_X25519", "FFDHE2048"})
    public void testSplitKeyShareRejectsNonHybridGroup(NamedGroup namedGroup) {
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                PQUtils.splitKeyShare(
                                        namedGroup, ConnectionEndType.CLIENT, new byte[1216]));
        assertEquals("Unsupported Hybrid PQ group: " + namedGroup, exception.getMessage());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testSplitKeyShareRejectsKeyShareShorterThanSplitIndex(NamedGroup namedGroup) {
        for (ConnectionEndType connectionEndType :
                new ConnectionEndType[] {ConnectionEndType.CLIENT, ConnectionEndType.SERVER}) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> PQUtils.splitKeyShare(namedGroup, connectionEndType, new byte[0]));
        }
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testSplitKeyShareAcceptsOversizedKeyShare(NamedGroup namedGroup) {
        int classicalKeyShareLength = PQUtils.getEcPublicKeyLength(namedGroup);
        int pqKeyShareLength = PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.CLIENT);
        int surplus = 84;

        byte[][] splitKeyShare =
                PQUtils.splitKeyShare(
                        namedGroup,
                        ConnectionEndType.CLIENT,
                        new byte[classicalKeyShareLength + pqKeyShareLength + surplus]);

        if (namedGroup.equals(NamedGroup.X25519_MLKEM768)) {
            assertEquals(classicalKeyShareLength + surplus, splitKeyShare[0].length);
            assertEquals(pqKeyShareLength, splitKeyShare[1].length);
        } else {
            assertEquals(classicalKeyShareLength, splitKeyShare[0].length);
            assertEquals(pqKeyShareLength + surplus, splitKeyShare[1].length);
        }
    }
}
