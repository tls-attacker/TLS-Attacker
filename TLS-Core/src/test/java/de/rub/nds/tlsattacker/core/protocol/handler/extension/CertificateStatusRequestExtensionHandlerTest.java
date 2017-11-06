/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.extension.CertificateStatusRequestExtensionParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.extension.CertificateStatusRequestExtensionPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class CertificateStatusRequestExtensionHandlerTest {
    private final CertificateStatusRequestType certificateStatusRequestExtensionRequestType = CertificateStatusRequestType.OCSP;
    private final byte[] certificateStatusRequestExtensionResponderIDList = new byte[] { 0x01 };
    private final byte[] certificateStatusRequestExtensionRequestExtension = new byte[] { 0x02 };
    private TlsContext context;
    private CertificateStatusRequestExtensionHandler handler;

    @Before
    public void setUp() {
        context = new TlsContext();
        handler = new CertificateStatusRequestExtensionHandler(context);
    }

    @Test
    public void testAdjustTLSContext() {
        CertificateStatusRequestExtensionMessage message = new CertificateStatusRequestExtensionMessage();
        message.setCertificateStatusRequestType(certificateStatusRequestExtensionRequestType
                .getCertificateStatusRequestValue());
        message.setResponderIDList(certificateStatusRequestExtensionResponderIDList);
        message.setRequestExtension(certificateStatusRequestExtensionRequestExtension);

        handler.adjustTLSContext(message);

        assertEquals(certificateStatusRequestExtensionRequestType,
                context.getCertificateStatusRequestExtensionRequestType());
        assertArrayEquals(certificateStatusRequestExtensionResponderIDList,
                context.getCertificateStatusRequestExtensionResponderIDList());
        assertArrayEquals(certificateStatusRequestExtensionRequestExtension,
                context.getCertificateStatusRequestExtensionRequestExtension());
    }

    @Test
    public void testGetParser() {
        assertTrue(handler.getParser(new byte[0], 0) instanceof CertificateStatusRequestExtensionParser);
    }

    @Test
    public void testGetPreparator() {
        assertTrue(handler.getPreparator(new CertificateStatusRequestExtensionMessage()) instanceof CertificateStatusRequestExtensionPreparator);
    }

    @Test
    public void testGetSerializer() {
        assertTrue(handler.getSerializer(new CertificateStatusRequestExtensionMessage()) instanceof CertificateStatusRequestExtensionSerializer);
    }

}
