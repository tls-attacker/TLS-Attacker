/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import org.junit.jupiter.api.Test;

public class CertificateStatusRequestExtensionHandlerTest
        extends AbstractExtensionMessageHandlerTest<
                CertificateStatusRequestExtensionMessage,
                CertificateStatusRequestExtensionHandler> {
    private final CertificateStatusRequestType certificateStatusRequestExtensionRequestType =
            CertificateStatusRequestType.OCSP;
    private final byte[] certificateStatusRequestExtensionResponderIDList = new byte[] {0x01};
    private final byte[] certificateStatusRequestExtensionRequestExtension = new byte[] {0x02};

    public CertificateStatusRequestExtensionHandlerTest() {
        super(
                CertificateStatusRequestExtensionMessage::new,
                CertificateStatusRequestExtensionHandler::new);
    }

    @Test
    @Override
    public void testadjustTLSExtensionContext() {
        CertificateStatusRequestExtensionMessage message =
                new CertificateStatusRequestExtensionMessage();
        message.setCertificateStatusRequestType(
                certificateStatusRequestExtensionRequestType.getCertificateStatusRequestValue());
        message.setResponderIDList(certificateStatusRequestExtensionResponderIDList);
        message.setRequestExtension(certificateStatusRequestExtensionRequestExtension);

        handler.adjustContext(message);

        assertEquals(
                certificateStatusRequestExtensionRequestType,
                context.getCertificateStatusRequestExtensionRequestType());
        assertArrayEquals(
                certificateStatusRequestExtensionResponderIDList,
                context.getCertificateStatusRequestExtensionResponderIDList());
        assertArrayEquals(
                certificateStatusRequestExtensionRequestExtension,
                context.getCertificateStatusRequestExtensionRequestExtension());
    }
}
