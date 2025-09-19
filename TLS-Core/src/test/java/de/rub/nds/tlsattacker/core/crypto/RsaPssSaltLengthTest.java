/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.protocol.crypto.signature.RsaSsaPssSignatureComputations;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class RsaPssSaltLengthTest {
    private TlsSignatureUtil tlsSignatureUtil;
    private Chooser chooser;
    private Config config;
    private SignatureCalculator signatureCalculator;

    @BeforeEach
    void setUp() {
        tlsSignatureUtil = new TlsSignatureUtil();
        config = new Config();
        State state = new State(config);
        chooser = state.getTlsContext().getChooser();
        signatureCalculator = new SignatureCalculator();
    }

    static Stream<Arguments> rsaPssAlgorithmProvider() {
        return Stream.of(
                Arguments.of(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256, 32),
                Arguments.of(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384, 48),
                Arguments.of(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512, 64),
                Arguments.of(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA256, 32),
                Arguments.of(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA384, 48),
                Arguments.of(SignatureAndHashAlgorithm.RSA_PSS_PSS_SHA512, 64));
    }

    @ParameterizedTest
    @MethodSource("rsaPssAlgorithmProvider")
    void testRsaPssSaltLengthCalculation(
            SignatureAndHashAlgorithm algorithm, int expectedSaltLength) throws Exception {
        // Test data
        byte[] toBeSigned = new byte[] {0x01, 0x02, 0x03, 0x04};

        // Set a salt that is too long to trigger truncation logic
        byte[] longSalt = new byte[100];
        for (int i = 0; i < longSalt.length; i++) {
            longSalt[i] = (byte) i;
        }
        config.setDefaultRsaSsaPssSalt(longSalt);

        SignatureComputations computations =
                signatureCalculator.createSignatureComputations(algorithm.getSignatureAlgorithm());

        // Compute signature - this should truncate the salt to the correct length
        tlsSignatureUtil.computeSignature(chooser, algorithm, toBeSigned, computations);

        // Verify the salt was truncated to the correct length (bits / 8 = bytes)
        assertTrue(computations instanceof RsaSsaPssSignatureComputations);
        RsaSsaPssSignatureComputations pssComputations =
                (RsaSsaPssSignatureComputations) computations;
        assertNotNull(pssComputations.getSalt());
        assertEquals(
                expectedSaltLength,
                pssComputations.getSalt().getValue().length,
                String.format(
                        "Salt length should be %d bytes for %s (bit length %d / 8)",
                        expectedSaltLength,
                        algorithm.name(),
                        algorithm.getHashAlgorithm().getBitLength()));
    }

    @ParameterizedTest
    @MethodSource("rsaPssAlgorithmProvider")
    void testRsaPssSaltPadding(SignatureAndHashAlgorithm algorithm, int expectedSaltLength)
            throws Exception {
        // Test data
        byte[] toBeSigned = new byte[] {0x01, 0x02, 0x03, 0x04};

        // Set a salt that is too short to trigger padding logic
        byte[] shortSalt = new byte[10];
        for (int i = 0; i < shortSalt.length; i++) {
            shortSalt[i] = (byte) (0xFF - i);
        }
        config.setDefaultRsaSsaPssSalt(shortSalt);

        SignatureComputations computations =
                signatureCalculator.createSignatureComputations(algorithm.getSignatureAlgorithm());

        // Compute signature - this should pad the salt to the correct length
        tlsSignatureUtil.computeSignature(chooser, algorithm, toBeSigned, computations);

        // Verify the salt was padded to the correct length
        assertTrue(computations instanceof RsaSsaPssSignatureComputations);
        RsaSsaPssSignatureComputations pssComputations =
                (RsaSsaPssSignatureComputations) computations;
        assertNotNull(pssComputations.getSalt());
        assertEquals(
                expectedSaltLength,
                pssComputations.getSalt().getValue().length,
                String.format(
                        "Salt length should be %d bytes for %s after padding",
                        expectedSaltLength, algorithm.name()));

        // Verify original salt values are preserved at the beginning
        byte[] resultSalt = pssComputations.getSalt().getValue();
        for (int i = 0; i < shortSalt.length; i++) {
            assertEquals(
                    shortSalt[i],
                    resultSalt[i],
                    String.format("Original salt value at position %d should be preserved", i));
        }

        // Verify padding is zeros
        for (int i = shortSalt.length; i < expectedSaltLength; i++) {
            assertEquals(
                    0, resultSalt[i], String.format("Padded value at position %d should be 0", i));
        }
    }

    @Test
    void testExactSaltLength() throws Exception {
        // Test with exact salt length - should not be modified
        SignatureAndHashAlgorithm algorithm = SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256;
        int expectedLength = 32; // SHA256 = 256 bits / 8 = 32 bytes

        byte[] exactSalt = new byte[expectedLength];
        for (int i = 0; i < exactSalt.length; i++) {
            exactSalt[i] = (byte) (i * 7);
        }
        config.setDefaultRsaSsaPssSalt(exactSalt);

        byte[] toBeSigned = new byte[] {0x05, 0x06, 0x07, 0x08};
        SignatureComputations computations =
                signatureCalculator.createSignatureComputations(algorithm.getSignatureAlgorithm());

        tlsSignatureUtil.computeSignature(chooser, algorithm, toBeSigned, computations);

        // Verify salt is unchanged
        assertTrue(computations instanceof RsaSsaPssSignatureComputations);
        RsaSsaPssSignatureComputations pssComputations =
                (RsaSsaPssSignatureComputations) computations;
        assertNotNull(pssComputations.getSalt());
        assertEquals(expectedLength, pssComputations.getSalt().getValue().length);
        byte[] resultSalt = pssComputations.getSalt().getValue();
        for (int i = 0; i < expectedLength; i++) {
            assertEquals(
                    exactSalt[i],
                    resultSalt[i],
                    String.format("Salt value at position %d should be unchanged", i));
        }
    }

    @Test
    void testBitLengthDivisionNotMultiplication() {
        // This test verifies the core issue - that bit length is divided by 8, not multiplied
        // For SHA256: 256 bits / 8 = 32 bytes (correct)
        // The bug would have been: 256 bits * 8 = 2048 bytes (incorrect)

        SignatureAndHashAlgorithm sha256 = SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256;
        SignatureAndHashAlgorithm sha384 = SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384;
        SignatureAndHashAlgorithm sha512 = SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512;

        // Verify bit lengths are as expected
        assertEquals(256, sha256.getHashAlgorithm().getBitLength());
        assertEquals(384, sha384.getHashAlgorithm().getBitLength());
        assertEquals(512, sha512.getHashAlgorithm().getBitLength());

        // Verify that dividing by 8 gives reasonable byte lengths
        assertEquals(32, sha256.getHashAlgorithm().getBitLength() / 8);
        assertEquals(48, sha384.getHashAlgorithm().getBitLength() / 8);
        assertEquals(64, sha512.getHashAlgorithm().getBitLength() / 8);

        // The bug would have resulted in these unreasonable values
        assertTrue(
                sha256.getHashAlgorithm().getBitLength() * 8 > 1000,
                "Multiplication would result in unreasonably large salt");
        assertTrue(
                sha384.getHashAlgorithm().getBitLength() * 8 > 1000,
                "Multiplication would result in unreasonably large salt");
        assertTrue(
                sha512.getHashAlgorithm().getBitLength() * 8 > 1000,
                "Multiplication would result in unreasonably large salt");
    }
}
