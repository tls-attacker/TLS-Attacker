/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

public class SendDynamicClientKeyExchangeActionTest
        extends AbstractActionTest<SendDynamicClientKeyExchangeAction> {

    public SendDynamicClientKeyExchangeActionTest() {
        super(new SendDynamicClientKeyExchangeAction(), SendDynamicClientKeyExchangeAction.class);
        state.getConfig().setDefaultRunningMode(RunningModeType.CLIENT);
        TlsContext context = state.getTlsContext();
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        context.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    @Test
    public void testGetSendMessages() {
        assertTrue(
                action.getSendMessages() instanceof ArrayList
                        && action.getSendMessages().isEmpty());
        action.execute(state);
        assertTrue(
                action.getSendMessages() instanceof ArrayList
                        && action.getSendMessages().size() == 1
                        && action.getSendMessages().get(0) instanceof DHClientKeyExchangeMessage);
    }

    @Test
    public void testGetSendRecords() {
        assertTrue(
                action.getSendRecords() instanceof ArrayList && action.getSendRecords().isEmpty());
        action.execute(state);
        assertTrue(
                action.getSendRecords() instanceof ArrayList
                        && action.getSendRecords().size() == 1);
    }

    @Test
    public void testSetRecords() {
        action.execute(state);
        List<Record> expectedRecords = new ArrayList<>();
        action.setRecords(expectedRecords);
        assertEquals(expectedRecords, action.getSendRecords());
    }

    @Test
    public void testEquals() {
        assertEquals(action, action);
        assertNotEquals(null, action);
        assertNotEquals(new Object(), action);
    }

    @Test
    public void testToString() {
        assertEquals(
                "Send Dynamic Client Key Exchange Action: (not executed)\n\tMessages:\n",
                action.toString());
    }

    @Test
    public void testToCompactString() {
        assertEquals(
                "SendDynamicClientKeyExchangeAction [client] (no messages set)",
                action.toCompactString());
    }
}
