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
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CachedInfoExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.cachedinfo.CachedObject;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CachedObjectPreparator;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class CachedInfoExtensionParserTest
        extends AbstractExtensionParserTest<CachedInfoExtensionMessage, CachedInfoExtensionParser> {

    public CachedInfoExtensionParserTest() {
        super(
                CachedInfoExtensionMessage.class,
                CachedInfoExtensionParser::new,
                List.of(
                        Named.of(
                                "CachedInfoExtensionMessage::getCachedInfoLength",
                                CachedInfoExtensionMessage::getCachedInfoLength),
                        Named.of(
                                "CachedInfoExtensionMessage::getCachedInfoBytes",
                                CachedInfoExtensionMessage::getCachedInfoBytes)));
    }

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        ArrayConverter.hexStringToByteArray("0019000400020102"),
                        List.of(ConnectionEndType.SERVER),
                        ExtensionType.CACHED_INFO,
                        4,
                        List.of(
                                2,
                                new byte[] {0x01, 0x02},
                                Arrays.asList(
                                        new CachedObject((byte) 1, null, null),
                                        new CachedObject((byte) 2, null, null)))),
                Arguments.of(
                        ArrayConverter.hexStringToByteArray(
                                "0019000f000d01060102030405060203070809"),
                        List.of(),
                        ExtensionType.CACHED_INFO,
                        15,
                        List.of(
                                13,
                                ArrayConverter.hexStringToByteArray("01060102030405060203070809"),
                                Arrays.asList(
                                        new CachedObject(
                                                (byte) 1,
                                                6,
                                                ArrayConverter.hexStringToByteArray(
                                                        "010203040506")),
                                        new CachedObject(
                                                (byte) 2, 3, new byte[] {0x07, 0x08, 0x09})))));
    }

    @Override
    protected void assertExtensionMessageSpecific(
            List<Object> providedAdditionalValues, List<Object> expectedMessageSpecificValues) {
        super.assertExtensionMessageSpecific(
                providedAdditionalValues, expectedMessageSpecificValues);
        // noinspection unchecked
        assertCachedObjectList(
                (List<CachedObject>) expectedMessageSpecificValues.get(2), message.getCachedInfo());
    }

    private void assertCachedObjectList(List<CachedObject> expected, List<CachedObject> actual) {
        for (int i = 0; i < expected.size(); i++) {
            CachedObject expectedObject = expected.get(i);
            CachedObject actualObject = actual.get(i);

            CachedObjectPreparator preparator =
                    new CachedObjectPreparator(new TlsContext().getChooser(), expectedObject);
            preparator.prepare();

            assertEquals(
                    expectedObject.getCachedInformationType().getValue(),
                    actualObject.getCachedInformationType().getValue());

            if (expectedObject.getHashValueLength() != null
                    && expectedObject.getHashValueLength().getValue() != null) {
                assertEquals(
                        expectedObject.getHashValueLength().getValue(),
                        actualObject.getHashValueLength().getValue());
            } else {
                assertNull(actualObject.getHashValueLength());
            }
            if (expectedObject.getHashValue() != null
                    && expectedObject.getHashValue().getValue() != null) {
                assertArrayEquals(
                        expectedObject.getHashValue().getValue(),
                        actualObject.getHashValue().getValue());
            } else {
                assertNull(actualObject.getHashValue());
            }
        }
    }
}
