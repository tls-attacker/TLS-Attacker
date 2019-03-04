/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.tlsattacker.core.constants.CertificateStatusRequestType;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.protocol.message.extension.CertificateStatusRequestExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.extension.CertificateStatusRequestExtensionSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class CertificateStatusRequestExtensionPreparatorTest {

    private final CertificateStatusRequestType certificateStatusRequestExtensionRequestType = CertificateStatusRequestType.OCSP;
    private final byte[] certificateStatusRequestExtensionResponderIDList = new byte[] { 0x01 };
    private final int responderIDListLength = 1;
    private final byte[] certificateStatusRequestExtensionRequestExtension = new byte[] { 0x02 };
    private final int requestExtensionLength = 1;
    private TlsContext context;
    private CertificateStatusRequestExtensionMessage msg;
    private CertificateStatusRequestExtensionPreparator preparator;

    @Before
    public void setUp() {
        context = new TlsContext();
        msg = new CertificateStatusRequestExtensionMessage();
        preparator = new CertificateStatusRequestExtensionPreparator(context.getChooser(), msg,
                new CertificateStatusRequestExtensionSerializer(msg));
    }

    @Test
    public void testPreparator() {
        context.getConfig().setCertificateStatusRequestExtensionRequestType(
                certificateStatusRequestExtensionRequestType);
        context.getConfig().setCertificateStatusRequestExtensionResponderIDList(
                certificateStatusRequestExtensionResponderIDList);
        context.getConfig().setCertificateStatusRequestExtensionRequestExtension(
                certificateStatusRequestExtensionRequestExtension);

        preparator.prepare();

        assertArrayEquals(ExtensionType.STATUS_REQUEST.getValue(), msg.getExtensionType().getValue());
        assertEquals(certificateStatusRequestExtensionRequestType.getCertificateStatusRequestValue(), (long) msg
                .getCertificateStatusRequestType().getValue());
        assertEquals(responderIDListLength, (long) msg.getResponderIDListLength().getValue());
        assertArrayEquals(certificateStatusRequestExtensionResponderIDList, msg.getResponderIDList().getValue());
        assertEquals(requestExtensionLength, (long) msg.getRequestExtensionLength().getValue());
        assertArrayEquals(certificateStatusRequestExtensionRequestExtension, msg.getRequestExtension().getValue());
    }
}
