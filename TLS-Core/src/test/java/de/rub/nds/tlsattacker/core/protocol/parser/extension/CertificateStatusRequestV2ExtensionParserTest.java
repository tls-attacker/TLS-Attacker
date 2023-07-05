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
import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RequestItemV2Preparator;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.params.provider.Arguments;

public class CertificateStatusRequestV2ExtensionParserTest
        extends AbstractExtensionParserTest<
                CertificateStatusRequestV2ExtensionMessage,
                CertificateStatusRequestV2ExtensionParser> {

    public CertificateStatusRequestV2ExtensionParserTest() {
        super(
                CertificateStatusRequestV2ExtensionMessage.class,
                CertificateStatusRequestV2ExtensionParser::new,
                List.of(
                        Named.of(
                                "CertificateStatusRequestV2ExtensionMessage::getStatusRequestListLength",
                                CertificateStatusRequestV2ExtensionMessage
                                        ::getStatusRequestListLength),
                        Named.of(
                                "CertificateStatusRequestV2ExtensionMessage::getStatusRequestBytes",
                                CertificateStatusRequestV2ExtensionMessage
                                        ::getStatusRequestBytes)));
    }

    public static Stream<Arguments> provideTestVectors() {
        List<ResponderId> responderIdList =
                List.of(
                        new ResponderId(3, new byte[] {0x01, 0x02, 0x03}),
                        new ResponderId(4, new byte[] {0x04, 0x05, 0x06, 0x07}));
        byte[] responderIdListBytes = hexStringToByteArray("0003010203000404050607");
        List<RequestItemV2> requestItems =
                List.of(
                        new RequestItemV2(1, 21, 0xb, 6, hexStringToByteArray("010203040506")),
                        new RequestItemV2(1, 21, 0xb, 6, hexStringToByteArray("010203040506")));
        for (RequestItemV2 requestItem : requestItems) {
            requestItem.setResponderIdList(responderIdList);
            requestItem.setResponderIdListBytes(responderIdListBytes);
        }

        return Stream.of(
                Arguments.of(
                        hexStringToByteArray(
                                "001100340030010015000B00030102030004040506070006010203040506010015000B00030102030004040506070006010203040506"),
                        List.of(),
                        ExtensionType.STATUS_REQUEST_V2,
                        52,
                        List.of(
                                48,
                                hexStringToByteArray(
                                        "010015000B00030102030004040506070006010203040506010015000B00030102030004040506070006010203040506"),
                                requestItems)));
    }

    @Override
    protected void assertExtensionMessageSpecific(
            List<Object> providedAdditionalValues, List<Object> expectedMessageSpecificValues) {
        super.assertExtensionMessageSpecific(
                providedAdditionalValues, expectedMessageSpecificValues);
        // noinspection unchecked
        assertRequestItemV2List(
                (List<RequestItemV2>) expectedMessageSpecificValues.get(2),
                message.getStatusRequestList());
    }

    public static void assertRequestItemV2List(
            List<RequestItemV2> listExpected, List<RequestItemV2> listActual) {
        RequestItemV2 itemExpected;
        RequestItemV2 itemActual;

        for (int i = 0; i < listExpected.size(); i++) {
            itemExpected = listExpected.get(i);
            itemActual = listActual.get(i);

            RequestItemV2Preparator preparator =
                    new RequestItemV2Preparator(new TlsContext().getChooser(), itemExpected);
            preparator.prepare();

            assertArrayEquals(
                    itemExpected.getRequestExtensions().getValue(),
                    itemActual.getRequestExtensions().getValue());
            assertEquals(
                    itemExpected.getRequestExtensionsLength().getValue(),
                    itemActual.getRequestExtensionsLength().getValue());
            assertEquals(
                    itemExpected.getRequestLength().getValue(),
                    itemActual.getRequestLength().getValue());
            assertEquals(
                    itemExpected.getRequestType().getValue(),
                    itemActual.getRequestType().getValue());
            if (itemExpected.getResponderIdListBytes() != null
                    && itemExpected.getResponderIdListBytes().getValue() != null) {
                assertArrayEquals(
                        itemExpected.getResponderIdListBytes().getValue(),
                        itemActual.getResponderIdListBytes().getValue());
            } else {
                assertNull(itemActual.getResponderIdListBytes());
            }
            assertEquals(
                    itemExpected.getResponderIdListLength().getValue(),
                    itemActual.getResponderIdListLength().getValue());
            RequestItemV2ParserTest.assertResponderIdList(
                    itemExpected.getResponderIdList(), itemActual.getResponderIdList());
        }
    }
}
