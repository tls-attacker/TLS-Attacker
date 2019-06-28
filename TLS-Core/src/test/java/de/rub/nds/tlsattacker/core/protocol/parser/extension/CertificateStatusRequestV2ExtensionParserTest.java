/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.hexStringToByteArray;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.RequestItemV2Preparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import org.junit.Test;

public class CertificateStatusRequestV2ExtensionParserTest {
    public static void assertRequestItemV2List(List<RequestItemV2> listExpected, List<RequestItemV2> listActual) {
        RequestItemV2 itemExpected;
        RequestItemV2 itemActual;

        for (int i = 0; i < listExpected.size(); i++) {
            itemExpected = listExpected.get(i);
            itemActual = listActual.get(i);

            RequestItemV2Preparator preparator = new RequestItemV2Preparator(new TlsContext().getChooser(),
                    itemExpected);
            preparator.prepare();

            assertArrayEquals(itemExpected.getRequestExtensions().getValue(), itemActual.getRequestExtensions()
                    .getValue());
            assertEquals(itemExpected.getRequestExtensionsLength().getValue(), itemActual.getRequestExtensionsLength()
                    .getValue());
            assertEquals(itemExpected.getRequestLength().getValue(), itemActual.getRequestLength().getValue());
            assertEquals(itemExpected.getRequestType().getValue(), itemActual.getRequestType().getValue());
            if (itemExpected.getResponderIdListBytes() != null
                    && itemExpected.getResponderIdListBytes().getValue() != null) {
                assertArrayEquals(itemExpected.getResponderIdListBytes().getValue(), itemActual
                        .getResponderIdListBytes().getValue());
            } else {
                assertNull(itemActual.getResponderIdListBytes());
            }
            assertEquals(itemExpected.getResponderIdListLength().getValue(), itemActual.getResponderIdListLength()
                    .getValue());
            RequestItemV2ParserTest.assertResponderIdList(itemExpected.getResponderIdList(),
                    itemActual.getResponderIdList());
        }
    }

    private final int listLength = 48;
    private final List<RequestItemV2> list = Arrays.asList(new RequestItemV2(1, 21, 0xb, 6,
            hexStringToByteArray("010203040506")), new RequestItemV2(1, 21, 0xb, 6,
            hexStringToByteArray("010203040506")));
    private final List<ResponderId> respList = Arrays.asList(new ResponderId(3, new byte[] { 0x01, 0x02, 0x03 }),
            new ResponderId(4, new byte[] { 0x04, 0x05, 0x06, 0x07 }));
    private final byte[] respoderIdListBytes = hexStringToByteArray("0003010203000404050607");
    private final byte[] statusRequestBytes = hexStringToByteArray("010015000B00030102030004040506070006010203040506010015000B00030102030004040506070006010203040506");
    private final byte[] parseBytes = hexStringToByteArray("001100340030010015000B00030102030004040506070006010203040506010015000B00030102030004040506070006010203040506");
    private final int startPosition = 0;
    private final int extensionLength = 52;
    private final ExtensionType type = ExtensionType.STATUS_REQUEST_V2;

    @Test
    public void testParser() {
        list.get(0).setResponderIdList(respList);
        list.get(0).setResponderIdListBytes(respoderIdListBytes);
        list.get(1).setResponderIdList(respList);
        list.get(1).setResponderIdListBytes(respoderIdListBytes);
        CertificateStatusRequestV2ExtensionParser parser = new CertificateStatusRequestV2ExtensionParser(startPosition,
                parseBytes);
        CertificateStatusRequestV2ExtensionMessage msg = parser.parse();

        assertArrayEquals(type.getValue(), msg.getExtensionType().getValue());
        assertEquals(extensionLength, (long) msg.getExtensionLength().getValue());
        assertEquals(listLength, (long) msg.getStatusRequestListLength().getValue());
        assertArrayEquals(statusRequestBytes, msg.getStatusRequestBytes().getValue());
        assertRequestItemV2List(list, msg.getStatusRequestList());

    }

}
