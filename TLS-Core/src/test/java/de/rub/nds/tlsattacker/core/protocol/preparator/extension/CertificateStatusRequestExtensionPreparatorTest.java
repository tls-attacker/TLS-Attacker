/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestExtensionSerializer;
import org.junit.jupiter.api.Test;

public class CertificateStatusRequestExtensionPreparatorTest
        extends AbstractExtensionMessagePreparatorTest<
                CertificateStatusRequestExtensionMessage,
                CertificateStatusRequestExtensionSerializer,
                CertificateStatusRequestExtensionPreparator> {

    public CertificateStatusRequestExtensionPreparatorTest() {
        super(
                CertificateStatusRequestExtensionMessage::new,
                CertificateStatusRequestExtensionSerializer::new,
                CertificateStatusRequestExtensionPreparator::new);
    }

    @Test
    @Override
    public void testPrepare() {
        byte[] certificateStatusRequestExtensionResponderIDList = new byte[] {0x01};
        byte[] certificateStatusRequestExtensionRequestExtension = new byte[] {0x02};

        context.getConfig()
                .setCertificateStatusRequestExtensionRequestType(CertificateStatusRequestType.OCSP);
        context.getConfig()
                .setCertificateStatusRequestExtensionResponderIDList(
                        certificateStatusRequestExtensionResponderIDList);
        context.getConfig()
                .setCertificateStatusRequestExtensionRequestExtension(
                        certificateStatusRequestExtensionRequestExtension);

        preparator.prepare();

        assertArrayEquals(
                ExtensionType.STATUS_REQUEST.getValue(), message.getExtensionType().getValue());
        assertEquals(
                CertificateStatusRequestType.OCSP.getCertificateStatusRequestValue(),
                message.getCertificateStatusRequestType().getValue());
        assertEquals(1, message.getResponderIDListLength().getValue());
        assertArrayEquals(
                certificateStatusRequestExtensionResponderIDList,
                message.getResponderIDList().getValue());
        assertEquals(1, message.getRequestExtensionLength().getValue());
        assertArrayEquals(
                certificateStatusRequestExtensionRequestExtension,
                message.getRequestExtension().getValue());
    }
}
