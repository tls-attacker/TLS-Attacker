/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestV2ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.RequestItemV2;
import de.rub.nds.tlsattacker.core.protocol.message.extension.statusrequestv2.ResponderId;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestV2ExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestV2ExtensionParserTest;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateStatusRequestV2ExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestV2ExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.Arrays;
import java.util.List;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class CertificateStatusRequestV2ExtensionHandlerTest {
    private final List<RequestItemV2> itemList = Arrays.asList(new RequestItemV2(1, 1, 1, 0, new byte[] { 0x02 }));
    private final List<ResponderId> idList = Arrays.asList(new ResponderId(1, new byte[] { 0x01 }));
    private CertificateStatusRequestV2ExtensionHandler handler;
    private TlsContext context;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new CertificateStatusRequestV2ExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        itemList.get(0).setResponderIdList(idList);
        CertificateStatusRequestV2ExtensionMessage msg = new CertificateStatusRequestV2ExtensionMessage();
        msg.setStatusRequestList(itemList);

        handler.adjustTLSContext(msg);

        CertificateStatusRequestV2ExtensionParserTest.assertRequestItemV2List(itemList,
                context.getStatusRequestV2RequestList());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof CertificateStatusRequestV2ExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new CertificateStatusRequestV2ExtensionMessage()) instanceof CertificateStatusRequestV2ExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new CertificateStatusRequestV2ExtensionMessage()) instanceof CertificateStatusRequestV2ExtensionSerializer);
    }
}
