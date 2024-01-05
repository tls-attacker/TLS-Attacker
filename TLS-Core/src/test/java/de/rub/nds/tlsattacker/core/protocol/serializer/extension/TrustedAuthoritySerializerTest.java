/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.tlsattacker.core.constants.TrustedCaIndicationIdentifierType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.trustedauthority.TrustedAuthority;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.TrustedAuthorityParserTest;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class TrustedAuthoritySerializerTest {

    public static Stream<Arguments> provideTestVectors() {
        return TrustedAuthorityParserTest.provideTestVectors();
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testSerialize(
            byte[] expectedTrustedAuthorityBytes,
            TrustedCaIndicationIdentifierType providedIdentifierType,
            byte[] providedSha1Hash,
            Integer providedDistinguishedNameLength,
            byte[] providedDistinguishedName) {
        TrustedAuthority trustedAuthority = new TrustedAuthority();
        trustedAuthority.setIdentifierType(providedIdentifierType.getValue());
        trustedAuthority.setSha1Hash(providedSha1Hash);
        if (providedDistinguishedNameLength != null) {
            trustedAuthority.setDistinguishedNameLength(providedDistinguishedNameLength);
        }
        trustedAuthority.setDistinguishedName(providedDistinguishedName);
        byte[] actualBytes = new TrustedAuthoritySerializer(trustedAuthority).serialize();
        assertArrayEquals(expectedTrustedAuthorityBytes, actualBytes);
    }
}
