/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestV2ExtensionParserTest;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestV2ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class CertificateStatusRequestV2ExtensionPreparatorTest {

    private final int listLength = 12;
    private final List<RequestItemV2> list = Arrays.asList(new RequestItemV2(1, 1, 1, 1, new byte[] { 0x01, 0x02 }));
    private final List<ResponderId> respList = Arrays.asList(new ResponderId(1, new byte[] { 1 }));
    private final byte[] respListBytes = new byte[] { 0x01, 0x02 };

    @Test
    public void testPreparator() {
        for (ResponderId item : respList) {
            ResponderIdPreparator idPreparator = new ResponderIdPreparator(new TlsContext().getChooser(), item);
            idPreparator.prepare();
        }

        for (RequestItemV2 item : list) {
            RequestItemV2Preparator itemPreparator = new RequestItemV2Preparator(new TlsContext().getChooser(), item);
            itemPreparator.prepare();
        }
        list.get(0).setResponderIdList(respList);
        list.get(0).setResponderIdListBytes(respListBytes);
        TlsContext context = new TlsContext();
        CertificateStatusRequestV2ExtensionMessage msg = new CertificateStatusRequestV2ExtensionMessage();
        context.getConfig().setStatusRequestV2RequestList(list);

        CertificateStatusRequestV2ExtensionPreparator preparator = new CertificateStatusRequestV2ExtensionPreparator(
                context.getChooser(), msg, new CertificateStatusRequestV2ExtensionSerializer(msg));
        preparator.prepare();

        CertificateStatusRequestV2ExtensionParserTest.assertRequestItemV2List(list, msg.getStatusRequestList());
        assertEquals(listLength, (long) msg.getStatusRequestListLength().getValue());

    }
}
