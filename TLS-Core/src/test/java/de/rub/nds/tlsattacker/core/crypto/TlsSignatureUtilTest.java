/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import de.rub.nds.protocol.crypto.signature.RsaSsaPssSignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

public class TlsSignatureUtilTest {
    private TlsSignatureUtil tlsSignatureUtil;
    private Chooser chooser;

    @BeforeEach
    void setUp() {
        tlsSignatureUtil = new TlsSignatureUtil();
        State state = new State(new Config());
        chooser = state.getTlsContext().getChooser();
    }

    static Stream<SignatureAndHashAlgorithm> signatureAndHashAlgorithmProvider() {
        return SignatureAndHashAlgorithm.getImplemented().stream()
                .map(algorithm -> (SignatureAndHashAlgorithm) algorithm);
    }

    public List<byte[]> getTestValues() {
        List<byte[]> testValues = new ArrayList<>();
        testValues.add(new byte[] {0x00, 0x01, 0x02, 0x03});
        testValues.add(new byte[0]);
        testValues.add(new byte[1]);
        testValues.add(new byte[100]);
        testValues.add(new byte[1000]);
        testValues.add(new byte[10000]);
        return testValues;
    }

    @ParameterizedTest
    @MethodSource("signatureAndHashAlgorithmProvider")
    void testComputeSignature(SignatureAndHashAlgorithm algorithm) {
        SignatureCalculator signatureCalculator = new SignatureCalculator();
        for (byte[] value : getTestValues()) {
            SignatureComputations computations =
                    signatureCalculator.createSignatureComputations(
                            algorithm.getSignatureAlgorithm());
            assertDoesNotThrow(
                    () ->
                            tlsSignatureUtil.computeSignature(
                                    chooser, algorithm, value, computations));
        }
    }

    @Test
    void testRsaPssSaltHandling() {
        // Test with different salt lengths to ensure proper random salt generation
        SignatureAndHashAlgorithm[] pssAlgorithms = {
            SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256,
            SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384,
            SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512
        };

        for (SignatureAndHashAlgorithm algorithm : pssAlgorithms) {
            // Test with incorrect salt length (should generate new random salt)
            Config config = chooser.getConfig();
            config.setDefaultRsaSsaPssSalt(new byte[10]); // Incorrect length

            RsaSsaPssSignatureComputations computations = new RsaSsaPssSignatureComputations();
            byte[] testData = new byte[] {0x01, 0x02, 0x03, 0x04};

            assertDoesNotThrow(
                    () ->
                            tlsSignatureUtil.computeSignature(
                                    chooser, algorithm, testData, computations));

            // Verify that salt was generated with correct length
            byte[] salt = computations.getSalt().getValue();
            int expectedSaltLength = algorithm.getHashAlgorithm().getBitLength() / 8;
            assertEquals(
                    expectedSaltLength,
                    salt.length,
                    "Salt length should match hash algorithm output length for " + algorithm);

            // Verify that salt is not all zeros (was properly randomized)
            byte[] allZeros = new byte[expectedSaltLength];
            assertNotEquals(
                    Arrays.toString(allZeros),
                    Arrays.toString(salt),
                    "Salt should be randomized, not all zeros");
        }
    }
}
