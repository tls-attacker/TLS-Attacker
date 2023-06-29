/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.hexStringToByteArray;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ResponderIdPreparator;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class RequestItemV2ParserTest {

    public static Stream<Arguments> provideTestVectors() {
        return Stream.of(
                Arguments.of(
                        hexStringToByteArray("010015000B00030102030004040506070006010203040506"),
                        1,
                        21,
                        0x0b,
                        hexStringToByteArray("0003010203000404050607"),
                        List.of(
                                new ResponderId(3, new byte[] {0x01, 0x02, 0x03}),
                                new ResponderId(4, new byte[] {0x04, 0x05, 0x06, 0x07})),
                        6,
                        hexStringToByteArray("010203040506")));
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public void testParse(
            byte[] providedRequestItemV2Bytes,
            int expectedRequestType,
            int expectedRequestLength,
            int expectedResponderIdListLength,
            byte[] expectedResponderIdListBytes,
            List<ResponderId> expectedResponderIdList,
            int expectedRequestExtensionsLength,
            byte[] expectedRequestExtensions) {
        RequestItemV2Parser parser =
                new RequestItemV2Parser(new ByteArrayInputStream(providedRequestItemV2Bytes));
        RequestItemV2 item = new RequestItemV2();
        parser.parse(item);

        assertEquals(expectedRequestType, item.getRequestType().getValue());
        assertEquals(expectedRequestLength, item.getRequestLength().getValue());
        assertEquals(expectedResponderIdListLength, item.getResponderIdListLength().getValue());
        assertArrayEquals(expectedResponderIdListBytes, item.getResponderIdListBytes().getValue());
        assertResponderIdList(expectedResponderIdList, item.getResponderIdList());
        assertEquals(
                expectedRequestExtensionsLength,
                (long) item.getRequestExtensionsLength().getValue());
        assertArrayEquals(expectedRequestExtensions, item.getRequestExtensions().getValue());
    }

    public static void assertResponderIdList(
            List<ResponderId> listExpected, List<ResponderId> listActual) {
        ResponderId itemExpected;
        ResponderId itemActual;
        for (int i = 0; i < listExpected.size(); i++) {
            itemExpected = listExpected.get(i);
            itemActual = listActual.get(i);
            ResponderIdPreparator preparator =
                    new ResponderIdPreparator(new TlsContext().getChooser(), itemExpected);
            preparator.prepare();

            assertEquals(
                    itemExpected.getIdLength().getValue(), itemActual.getIdLength().getValue());
            assertArrayEquals(itemExpected.getId().getValue(), itemActual.getId().getValue());
        }
    }
}
