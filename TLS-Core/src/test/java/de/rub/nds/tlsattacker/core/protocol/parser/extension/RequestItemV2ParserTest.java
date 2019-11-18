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
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.ResponderIdPreparator;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class RequestItemV2ParserTest {
    public static void assertResponderIdList(List<ResponderId> listExpected, List<ResponderId> listActual) {
        ResponderId itemExpected;
        ResponderId itemActual;
        for (int i = 0; i < listExpected.size(); i++) {
            itemExpected = listExpected.get(i);
            itemActual = listActual.get(i);
            ResponderIdPreparator preparator = new ResponderIdPreparator(new TlsContext().getChooser(), itemExpected);
            preparator.prepare();

            assertEquals(itemExpected.getIdLength().getValue(), itemActual.getIdLength().getValue());
            assertArrayEquals(itemExpected.getId().getValue(), itemActual.getId().getValue());
        }
    }

    private final int startParsing = 0;
    private final int requestType = 1;
    private final int requestLength = 21;
    private final int responderIdLength = 0x0b;
    private final List<ResponderId> responderIdList = Arrays.asList(
            new ResponderId(3, new byte[] { 0x01, 0x02, 0x03 }), new ResponderId(4,
                    new byte[] { 0x04, 0x05, 0x06, 0x07 }));
    private final int requestExtensionLength = 6;
    private final byte[] requestExtension = hexStringToByteArray("010203040506");
    private final byte[] parsingBytes = hexStringToByteArray("010015000B00030102030004040506070006010203040506");
    private final byte[] responderIdBytes = hexStringToByteArray("0003010203000404050607");

    @Test
    public void testParser() {
        RequestItemV2Parser parser = new RequestItemV2Parser(startParsing, parsingBytes);
        RequestItemV2 item = parser.parse();

        assertEquals(requestType, (long) item.getRequestType().getValue());
        assertEquals(requestLength, (long) item.getRequestLength().getValue());
        assertEquals(responderIdLength, (long) item.getResponderIdListLength().getValue());
        assertArrayEquals(responderIdBytes, item.getResponderIdListBytes().getValue());
        assertResponderIdList(responderIdList, item.getResponderIdList());
        assertEquals(requestExtensionLength, (long) item.getRequestExtensionsLength().getValue());
        assertArrayEquals(requestExtension, item.getRequestExtensions().getValue());

    }

}
