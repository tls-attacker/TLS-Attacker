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

import de.rub.nds.protocol.constants.MlKemParameters;
import de.rub.nds.protocol.crypto.kem.MlKemEncapsulation;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import java.security.SecureRandom;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Verifies that our NamedGroups are wired to the right ML-KEM parameter set. The ML-KEM
 * computations themselves are covered by the known answer tests of Protocol-Attacker.
 */
public class MlkemTest {

    /**
     * A hybrid group has to run the very same ML-KEM computation as the pure group it embeds, so
     * encapsulating under both with the same randomness has to produce the same result.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("provideHybridGroups")
    public void testHybridGroupUsesItsMlKemParameterSet(NamedGroup hybridGroup) {
        NamedGroup pqGroup = hybridGroup.getHybridPostQuantumNamedGroup();
        KeyShareEntry clientEntry = new KeyShareEntry();
        KeyShareCalculator.createMLKEMKeyShare(pqGroup, clientEntry, new SecureRandom());
        byte[] encapsulationKey = clientEntry.getMLKEMPublicKey().getValue();
        byte[] encapsulationRandomness = new byte[32];
        new SecureRandom().nextBytes(encapsulationRandomness);

        MlKemEncapsulation viaHybridGroup =
                KeyShareCalculator.mlkemEncaps(
                        hybridGroup,
                        encapsulationKey,
                        new FixedSecureRandom(encapsulationRandomness));
        MlKemEncapsulation viaPqGroup =
                KeyShareCalculator.mlkemEncaps(
                        pqGroup, encapsulationKey, new FixedSecureRandom(encapsulationRandomness));

        assertArrayEquals(viaPqGroup.getCiphertext(), viaHybridGroup.getCiphertext());
        assertArrayEquals(viaPqGroup.getSharedSecret(), viaHybridGroup.getSharedSecret());
    }

    /** The key share a group generates has to have the size its parameter set defines. */
    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {
                "MLKEM512",
                "MLKEM768",
                "MLKEM1024",
                "X25519_MLKEM768",
                "SECP256R1_MLKEM768",
                "SECP384R1_MLKEM1024"
            })
    public void testKeyShareSizesMatchParameterSet(NamedGroup namedGroup) {
        MlKemParameters parameters =
                (MlKemParameters) namedGroup.getAnyInvolvedPqGroup().getAsymmetricParameters();
        KeyShareEntry entry = new KeyShareEntry();

        KeyShareCalculator.createMLKEMKeyShare(namedGroup, entry, new SecureRandom());

        assertEquals(
                parameters.getEncapsulationKeySizeBytes(),
                entry.getMLKEMPublicKey().getValue().length);
        assertEquals(parameters.getDecapsulationKeySizeBytes(), entry.getMLKEMPrivateKey().length);
        assertEquals(
                parameters.getCiphertextSizeBytes(),
                KeyShareCalculator.mlkemEncaps(
                                namedGroup,
                                entry.getMLKEMPublicKey().getValue(),
                                new SecureRandom())
                        .getCiphertext()
                        .length);
    }

    /** Encapsulating and decapsulating through the NamedGroup API has to agree on the secret. */
    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM512", "MLKEM768", "MLKEM1024"})
    public void testEncapsAndDecapsAgreeOnSharedSecret(NamedGroup namedGroup) {
        KeyShareEntry entry = new KeyShareEntry();
        KeyShareCalculator.createMLKEMKeyShare(namedGroup, entry, new SecureRandom());

        MlKemEncapsulation encapsulation =
                KeyShareCalculator.mlkemEncaps(
                        namedGroup, entry.getMLKEMPublicKey().getValue(), new SecureRandom());

        assertArrayEquals(
                encapsulation.getSharedSecret(),
                KeyShareCalculator.mlkemDecaps(
                        namedGroup,
                        entry.getMLKEMPrivateKeyContainer(),
                        encapsulation.getCiphertext()));
    }

    public static Stream<Arguments> provideHybridGroups() {
        return Stream.of(
                Arguments.of(NamedGroup.X25519_MLKEM768),
                Arguments.of(NamedGroup.SECP256R1_MLKEM768),
                Arguments.of(NamedGroup.SECP384R1_MLKEM1024));
    }

    /** Hands out a fixed byte string, so that two encapsulations can be compared. */
    private static class FixedSecureRandom extends SecureRandom {

        private static final long serialVersionUID = 1L;

        private final byte[] data;

        private int offset;

        FixedSecureRandom(byte[] data) {
            this.data = data.clone();
        }

        @Override
        public void nextBytes(byte[] output) {
            if (offset + output.length > data.length) {
                throw new IllegalStateException(
                        "Requested "
                                + (offset + output.length)
                                + " bytes but only "
                                + data.length
                                + " are available");
            }
            System.arraycopy(data, offset, output, 0, output.length);
            offset += output.length;
        }
    }
}
