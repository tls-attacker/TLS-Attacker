/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.JAXBException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.xml.stream.XMLStreamException;
import org.junit.jupiter.api.Test;

public class ReceiveActionTest extends AbstractActionTest<ReceiveAction> {

    private final TlsContext context;
    private final AlertMessage alertMessage;

    public ReceiveActionTest() {
        super(new ReceiveAction(new AlertMessage()), ReceiveAction.class);
        context = state.getTlsContext();
        context.setTransportHandler(new FakeTcpTransportHandler(ConnectionEndType.CLIENT));
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);

        alertMessage = (AlertMessage) action.getExpectedMessages().get(0);
        alertMessage.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        alertMessage.setDescription(AlertDescription.DECODE_ERROR.getValue());
        alertMessage.setLevel(AlertLevel.FATAL.getValue());
    }

    /**
     * Test of execute method, of class ReceiveAction.
     *
     * @throws java.lang.Exception
     */
    @Test
    @Override
    public void testExecute() throws Exception {
        ((FakeTcpTransportHandler) context.getTransportHandler())
                .setFetchableByte(new byte[] {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50});
        super.testExecute();
    }

    @Test
    public void testJAXB() throws JAXBException, IOException, XMLStreamException {
        SilentByteArrayOutputStream outputStream = new SilentByteArrayOutputStream();
        action.filter();
        ActionIO.write(outputStream, action);
        TlsAction action2 = ActionIO.read(new ByteArrayInputStream(outputStream.toByteArray()));
        action.normalize();
        action2.normalize();
        assertEquals(action, action2);
    }
}
