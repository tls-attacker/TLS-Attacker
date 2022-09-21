/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.JAXB;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.io.StringWriter;

public class ReceiveActionTest extends AbstractActionTest<ReceiveAction> {

    private final TlsContext context;

    public ReceiveActionTest() {
        super(new ReceiveAction(), ReceiveAction.class);
        context = state.getTlsContext();
        context.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        context.setRecordLayer(new TlsRecordLayer(context));

        AlertMessage alert = new AlertMessage(context.getConfig());
        alert.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        alert.setDescription(AlertDescription.DECODE_ERROR.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        action.setExpectedMessages(alert);
    }

    /**
     * Test of execute method, of class ReceiveAction.
     */
    @Test
    @Override
    public void testExecute() throws Exception {
        ((FakeTransportHandler) context.getTransportHandler())
            .setFetchableByte(new byte[] { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50 });
        super.testExecute();
    }

    @Test
    public void testJAXB() {
        StringWriter writer = new StringWriter();
        action.filter();
        JAXB.marshal(action, writer);
        TlsAction action2 = JAXB.unmarshal(new StringReader(writer.getBuffer().toString()), ReceiveAction.class);
        action.normalize();
        action2.normalize();
        assertEquals(action, action2);
    }
}
