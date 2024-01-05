/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestV2ExtensionParserTest;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestV2ExtensionSerializer;
import java.util.List;
import org.junit.jupiter.api.Test;

public class CertificateStatusRequestV2ExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                CertificateStatusRequestV2ExtensionMessage,
                CertificateStatusRequestV2ExtensionSerializer,
                CertificateStatusRequestV2ExtensionPreparator> {

    public CertificateStatusRequestV2ExtensionPreparatorTest() {
        super(
                CertificateStatusRequestV2ExtensionMessage::new,
                CertificateStatusRequestV2ExtensionSerializer::new,
                CertificateStatusRequestV2ExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        List<RequestItemV2> list = List.of(new RequestItemV2(1, 1, 1, 1, new byte[] {0x01, 0x02}));
        List<ResponderId> respList = List.of(new ResponderId(1, new byte[] {1}));
        byte[] respListBytes = new byte[] {0x01, 0x02};

        for (ResponderId item : respList) {
            ResponderIdPreparator idPreparator =
                    new ResponderIdPreparator(context.getChooser(), item);
            idPreparator.prepare();
        }

        for (RequestItemV2 item : list) {
            RequestItemV2Preparator itemPreparator =
                    new RequestItemV2Preparator(context.getChooser(), item);
            itemPreparator.prepare();
        }
        list.get(0).setResponderIdList(respList);
        list.get(0).setResponderIdListBytes(respListBytes);
        context.getConfig().setStatusRequestV2RequestList(list);

        preparator.prepare();

        CertificateStatusRequestV2ExtensionParserTest.assertRequestItemV2List(
                list, message.getStatusRequestList());
        assertEquals(12, message.getStatusRequestListLength().getValue());
    }
}
