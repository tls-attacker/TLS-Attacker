/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class CertificateStatusRequestExtensionHandlerTest {

    private final CertificateStatusRequestType certificateStatusRequestExtensionRequestType =
        CertificateStatusRequestType.OCSP;
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
    public void testadjustContext() {
        CertificateStatusRequestExtensionMessage message = new CertificateStatusRequestExtensionMessage();
        message.setCertificateStatusRequestType(
            certificateStatusRequestExtensionRequestType.getCertificateStatusRequestValue());
        message.setResponderIDList(certificateStatusRequestExtensionResponderIDList);
        message.setRequestExtension(certificateStatusRequestExtensionRequestExtension);

        handler.adjustContext(message);

        assertEquals(certificateStatusRequestExtensionRequestType,
            context.getCertificateStatusRequestExtensionRequestType());
        assertArrayEquals(certificateStatusRequestExtensionResponderIDList,
            context.getCertificateStatusRequestExtensionResponderIDList());
        assertArrayEquals(certificateStatusRequestExtensionRequestExtension,
            context.getCertificateStatusRequestExtensionRequestExtension());
    }
}
