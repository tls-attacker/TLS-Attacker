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
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
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
    public void testGetSentMessages() {
        assertNull(action.getSentMessages());
        action.execute(state);
        assertTrue(
                action.getSentMessages() instanceof ArrayList
                        && action.getSentMessages().size() == 1
                        && action.getSentMessages().get(0) instanceof DHClientKeyExchangeMessage);
    }

    @Test
    public void testGetSentRecords() {
        assertNull(action.getSentRecords());
        action.execute(state);
        assertTrue(
                action.getSentRecords() instanceof ArrayList
                        && action.getSentRecords().size() == 1);
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
