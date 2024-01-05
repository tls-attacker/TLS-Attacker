/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.TrustedCaIndicationIdentifierType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import java.io.ByteArrayInputStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class TrustedAuthorityParserTest {

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        new byte[] {0},
                        TrustedCaIndicationIdentifierType.PRE_AGREED,
                        null,
                        null,
                        null),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "01da39a3ee5e6b4b0d3255bfef95601890afd80709"),
                        TrustedCaIndicationIdentifierType.KEY_SHA1_HASH,
                        ArrayConverter.hexStringToByteArray(
                                "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
                        null,
                        null),
                Arguments.of(
                        new byte[] {0x02, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05},
                        TrustedCaIndicationIdentifierType.X509_NAME,
                        null,
                        5,
                        new byte[] {0x01, 0x02, 0x03, 0x04, 0x05}),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "03da39a3ee5e6b4b0d3255bfef95601890afd80709"),
                        TrustedCaIndicationIdentifierType.CERT_SHA1_HASH,
                        ArrayConverter.hexStringToByteArray(
                                "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
                        null,
                        null));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedTrustedAuthorityBytes,
            TrustedCaIndicationIdentifierType expectedIdentifierType,
            byte[] expectedSha1Hash,
            Integer expectedDistinguishedNameLength,
            byte[] expectedDistinguishedName) {

        TrustedAuthorityParser parser =
                new TrustedAuthorityParser(new ByteArrayInputStream(providedTrustedAuthorityBytes));
        TrustedAuthority authority = new TrustedAuthority();
        parser.parse(authority);

        assertEquals(expectedIdentifierType.getValue(), authority.getIdentifierType().getValue());
        if (expectedSha1Hash != null) {
            assertArrayEquals(expectedSha1Hash, authority.getSha1Hash().getValue());
        } else {
            assertNull(authority.getSha1Hash());
        }
        if (expectedDistinguishedNameLength != null) {
            assertEquals(
                    expectedDistinguishedNameLength,
                    authority.getDistinguishedNameLength().getValue());
        } else {
            assertNull(authority.getDistinguishedNameLength());
        }
        if (expectedDistinguishedName != null) {
            assertArrayEquals(
                    expectedDistinguishedName, authority.getDistinguishedName().getValue());
        } else {
            assertNull(authority.getDistinguishedName());
        }
    }
}
