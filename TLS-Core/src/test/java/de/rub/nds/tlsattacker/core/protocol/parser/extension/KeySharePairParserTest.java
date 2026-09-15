/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.KeyShareCalculator;
import de.rub.nds.tlsattacker.core.crypto.pq.PQUtils;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

public class KeySharePairParserTest {

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        DataConverter.hexStringToByteArray(
                                "001D00202a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                        32,
                        DataConverter.hexStringToByteArray(
                                "2a981db6cdd02a06c1763102c9e741365ac4e6f72b3176a6bd6a3523d3ec0f4c"),
                        DataConverter.hexStringToByteArray("001D")));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedKeySharePairBytes,
            int expectedKeyShareLength,
            byte[] expectedKeyShare,
            byte[] expectedKeyShareType) {
        KeyShareEntryParser parser =
                new KeyShareEntryParser(
                        new ByteArrayInputStream(providedKeySharePairBytes),
                        false,
                        ConnectionEndType.CLIENT);
        KeyShareEntry entry = new KeyShareEntry();
        parser.parse(entry);

        assertEquals(expectedKeyShareLength, (int) entry.getPublicKeyLength().getValue());
        assertArrayEquals(expectedKeyShare, entry.getPublicKey().getValue());
        assertArrayEquals(expectedKeyShareType, entry.getGroup().getValue());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testParseClientHybridKeyShareSetsBothComponents(NamedGroup namedGroup) {
        byte[] classicalShare = filled(PQUtils.getEcPublicKeyLength(namedGroup), (byte) 0x04);
        byte[] encapsulationKey =
                filled(
                        PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.CLIENT),
                        (byte) 0x11);
        byte[] keyShare =
                PQUtils.concatenateHybridKeyShare(namedGroup, classicalShare, encapsulationKey);

        KeyShareEntry entry = parse(namedGroup, keyShare, ConnectionEndType.CLIENT);

        assertArrayEquals(keyShare, entry.getPublicKey().getValue());
        assertArrayEquals(classicalShare, entry.getDhPublicKey().getValue());
        assertArrayEquals(encapsulationKey, entry.getMlKemPublicKey().getValue());
        assertEquals(
                KeyShareCalculator.getMlKemParameters(namedGroup),
                entry.getMlKemPublicKeyContainer().getParameters());
        assertNull(entry.getMlKemCiphertext());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testParseServerHybridKeyShareSetsBothComponents(NamedGroup namedGroup) {
        byte[] classicalShare = filled(PQUtils.getEcPublicKeyLength(namedGroup), (byte) 0x04);
        byte[] ciphertext =
                filled(
                        PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.SERVER),
                        (byte) 0x22);
        byte[] keyShare = PQUtils.concatenateHybridKeyShare(namedGroup, classicalShare, ciphertext);

        KeyShareEntry entry = parse(namedGroup, keyShare, ConnectionEndType.SERVER);

        assertArrayEquals(keyShare, entry.getPublicKey().getValue());
        assertArrayEquals(classicalShare, entry.getDhPublicKey().getValue());
        assertArrayEquals(ciphertext, entry.getMlKemCiphertext().getValue());
        assertNull(entry.getMlKemPublicKey());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM512", "MLKEM768", "MLKEM1024"})
    public void testParsePureMlKemKeyShareSetsMlKemComponent(NamedGroup namedGroup) {
        byte[] encapsulationKey =
                filled(
                        PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.CLIENT),
                        (byte) 0x11);
        byte[] ciphertext =
                filled(
                        PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.SERVER),
                        (byte) 0x22);

        KeyShareEntry clientEntry = parse(namedGroup, encapsulationKey, ConnectionEndType.CLIENT);
        assertArrayEquals(encapsulationKey, clientEntry.getMlKemPublicKey().getValue());
        assertNull(clientEntry.getMlKemCiphertext());
        assertNull(clientEntry.getDhPublicKey());

        KeyShareEntry serverEntry = parse(namedGroup, ciphertext, ConnectionEndType.SERVER);
        assertArrayEquals(ciphertext, serverEntry.getMlKemCiphertext().getValue());
        assertNull(serverEntry.getMlKemPublicKey());
        assertNull(serverEntry.getDhPublicKey());
    }

    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"ECDH_X25519", "SECP256R1", "FFDHE2048"})
    public void testParseClassicalKeyShareSetsDhComponent(NamedGroup namedGroup) {
        byte[] keyShare = filled(32, (byte) 0x33);

        KeyShareEntry entry = parse(namedGroup, keyShare, ConnectionEndType.CLIENT);

        assertArrayEquals(keyShare, entry.getDhPublicKey().getValue());
        assertNull(entry.getMlKemPublicKey());
        assertNull(entry.getMlKemCiphertext());
    }

    /**
     * ML-KEM key shares of a group have a fixed length. A key share that does not match it cannot
     * be split, but must not fail the parser, as a peer may send it.
     */
    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"MLKEM768", "X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testParseMlKemKeyShareOfUnexpectedLengthLeavesComponentsUnset(
            NamedGroup namedGroup) {
        KeyShareEntry entry = parse(namedGroup, filled(23, (byte) 0x55), ConnectionEndType.CLIENT);

        assertArrayEquals(filled(23, (byte) 0x55), entry.getPublicKey().getValue());
        assertNull(entry.getDhPublicKey());
        assertNull(entry.getMlKemPublicKey());
        assertNull(entry.getMlKemCiphertext());
    }

    @Test
    public void testParseUnknownGroupLeavesComponentsUnset() {
        byte[] keyShare = filled(32, (byte) 0x66);
        KeyShareEntry entry =
                parse(
                        DataConverter.hexStringToByteArray("FFFE"),
                        keyShare,
                        ConnectionEndType.CLIENT);

        assertNull(entry.getGroupConfig());
        assertArrayEquals(keyShare, entry.getPublicKey().getValue());
        assertNull(entry.getDhPublicKey());
        assertNull(entry.getMlKemPublicKey());
        assertNull(entry.getMlKemCiphertext());
    }

    /** GREASE groups are known NamedGroups, but carry no key share components. */
    @Test
    public void testParseGreaseGroupLeavesComponentsUnset() {
        byte[] keyShare = filled(32, (byte) 0x66);
        KeyShareEntry entry = parse(NamedGroup.GREASE_00, keyShare, ConnectionEndType.CLIENT);

        assertEquals(NamedGroup.GREASE_00, entry.getGroupConfig());
        assertArrayEquals(keyShare, entry.getPublicKey().getValue());
        assertNull(entry.getDhPublicKey());
        assertNull(entry.getMlKemPublicKey());
        assertNull(entry.getMlKemCiphertext());
    }

    @Test
    public void testParseHelloRetryRequestFormLeavesComponentsUnset() {
        KeyShareEntryParser parser =
                new KeyShareEntryParser(
                        new ByteArrayInputStream(NamedGroup.X25519_MLKEM768.getValue()),
                        true,
                        ConnectionEndType.SERVER);
        KeyShareEntry entry = new KeyShareEntry();
        parser.parse(entry);

        assertEquals(NamedGroup.X25519_MLKEM768, entry.getGroupConfig());
        assertNull(entry.getPublicKey());
        assertNull(entry.getDhPublicKey());
        assertNull(entry.getMlKemPublicKey());
        assertNull(entry.getMlKemCiphertext());
    }

    /** The parsed components must concatenate back to the key share they were taken from. */
    @ParameterizedTest
    @EnumSource(
            value = NamedGroup.class,
            names = {"X25519_MLKEM768", "SECP256R1_MLKEM768", "SECP384R1_MLKEM1024"})
    public void testParsedComponentsConcatenateToTheKeyShare(NamedGroup namedGroup) {
        byte[] classicalShare = filled(PQUtils.getEcPublicKeyLength(namedGroup), (byte) 0x04);
        byte[] ciphertext =
                filled(
                        PQUtils.getPQKeyShareLength(namedGroup, ConnectionEndType.SERVER),
                        (byte) 0x22);

        KeyShareEntry entry =
                parse(
                        namedGroup,
                        PQUtils.concatenateHybridKeyShare(namedGroup, classicalShare, ciphertext),
                        ConnectionEndType.SERVER);

        assertNotNull(entry.getDhPublicKey());
        assertNotNull(entry.getMlKemCiphertext());
        assertArrayEquals(
                entry.getPublicKey().getValue(),
                PQUtils.concatenateHybridKeyShare(
                        namedGroup,
                        entry.getDhPublicKey().getValue(),
                        entry.getMlKemCiphertext().getValue()));
    }

    private static KeyShareEntry parse(
            NamedGroup namedGroup, byte[] keyShare, ConnectionEndType issuerEndType) {
        return parse(namedGroup.getValue(), keyShare, issuerEndType);
    }

    private static KeyShareEntry parse(
            byte[] groupBytes, byte[] keyShare, ConnectionEndType issuerEndType) {
        byte[] entryBytes =
                DataConverter.concatenate(
                        groupBytes,
                        DataConverter.intToBytes(
                                keyShare.length, ExtensionByteLength.KEY_SHARE_LENGTH),
                        keyShare);
        KeyShareEntryParser parser =
                new KeyShareEntryParser(new ByteArrayInputStream(entryBytes), false, issuerEndType);
        KeyShareEntry entry = new KeyShareEntry();
        parser.parse(entry);
        return entry;
    }

    private static byte[] filled(int length, byte value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, value);
        return bytes;
    }
}
