/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.CachedInfoType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

public class CachedObjectParserTest {

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(Arguments.of(new byte[] { 0x01 }, ConnectionEndType.SERVER, CachedInfoType.CERT, null, null),
            Arguments.of(new byte[] { 0x02 }, ConnectionEndType.SERVER, CachedInfoType.CERT_REQ, null, null),
            Arguments.of(new byte[] { 0x01, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, ConnectionEndType.CLIENT,
                CachedInfoType.CERT, 6, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }),
            Arguments.of(new byte[] { 0x02, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, ConnectionEndType.CLIENT,
                CachedInfoType.CERT_REQ, 6, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(byte[] providedCachedObjectBytes, ConnectionEndType providedSpeakingEndType,
        CachedInfoType expectedCachedInfoType, Integer expectedHashLength, byte[] expectedHash) {
        CachedObjectParser parser = new CachedObjectParser(0, providedCachedObjectBytes, providedSpeakingEndType);
        CachedObject cachedObject = parser.parse();

        assertEquals(expectedCachedInfoType.getValue(), (long) cachedObject.getCachedInformationType().getValue());

        if (expectedHashLength != null) {
            assertEquals(expectedHashLength, cachedObject.getHashValueLength().getValue());
        } else {
            assertNull(cachedObject.getHashValueLength());
        }
        if (expectedHash != null) {
            assertArrayEquals(expectedHash, cachedObject.getHashValue().getValue());
        } else {
            assertNull(cachedObject.getHashValue());
        }
    }

}
