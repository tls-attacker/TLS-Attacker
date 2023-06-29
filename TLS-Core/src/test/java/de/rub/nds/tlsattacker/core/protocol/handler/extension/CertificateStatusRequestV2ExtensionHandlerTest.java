/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestV2ExtensionParserTest;
import java.util.List;
import org.junit.jupiter.api.Test;

public class CertificateStatusRequestV2ExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                CertificateStatusRequestV2ExtensionMessage,
                CertificateStatusRequestV2ExtensionHandler> {
    private final List<RequestItemV2> itemList =
            List.of(new RequestItemV2(1, 1, 1, 0, new byte[] {0x02}));
    private final List<ResponderId> idList = List.of(new ResponderId(1, new byte[] {0x01}));

    public CertificateStatusRequestV2ExtensionHandlerTest() {
        super(
                CertificateStatusRequestV2ExtensionMessage::new,
                CertificateStatusRequestV2ExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        itemList.get(0).setResponderIdList(idList);
        CertificateStatusRequestV2ExtensionMessage msg =
                new CertificateStatusRequestV2ExtensionMessage();
        msg.setStatusRequestList(itemList);

        handler.adjustContext(msg);

        CertificateStatusRequestV2ExtensionParserTest.assertRequestItemV2List(
                itemList, context.getStatusRequestV2RequestList());
    }
}
