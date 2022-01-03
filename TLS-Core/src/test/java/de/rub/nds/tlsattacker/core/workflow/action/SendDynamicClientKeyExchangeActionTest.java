/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.util.ArrayList;
import java.util.List;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author mario
 */
public class SendDynamicClientKeyExchangeActionTest {

    private State state;
    private TlsContext tlsContext;
    private Config config;

    private SendDynamicClientKeyExchangeAction action;

    @Before
    public void setUp() {
        action = new SendDynamicClientKeyExchangeAction();

        // create Config to not overly rely on default values (aka. make sure
        // we're client)
        config = Config.createConfig();
        config.setDefaultRunningMode(RunningModeType.CLIENT);

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(config, trace);

        tlsContext = state.getTlsContext();
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordLayer(new TlsRecordLayer(tlsContext));
        tlsContext.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    @Test
    public void testExecute() {
        action.execute(state);
        assertTrue(action.executedAsPlanned());
        assertTrue(action.isExecuted());
        try {
            action.execute(state);
            fail(); // Code shouldn't be reached at all
        } catch (WorkflowExecutionException e) {
            assertTrue(e.getMessage().equals("Action already executed!"));
        } catch (Exception e) {
            // any other Exception than what should have been thrown appeared
            fail();
        }
    }

    @Test
    public void testGetSendMessages() {
        assertTrue(action.getSendMessages() instanceof ArrayList && action.getSendMessages().isEmpty());
        action.execute(state);
        assertTrue(action.getSendMessages() instanceof ArrayList && action.getSendMessages().size() == 1
            && action.getSendMessages().get(0) instanceof DHClientKeyExchangeMessage);
    }

    @Test
    public void testGetSendRecords() {
        assertTrue(action.getSendRecords() instanceof ArrayList && action.getSendRecords().isEmpty());
        action.execute(state);
        assertTrue(action.getSendRecords() instanceof ArrayList && action.getSendRecords().size() == 1
            && action.getSendRecords().get(0) instanceof AbstractRecord);
    }

    @Test
    public void testSetRecords() {
        action.execute(state);
        List<AbstractRecord> expectedRecords = new ArrayList<>();
        action.setRecords(expectedRecords);
        assertTrue(action.getSendRecords().equals(expectedRecords));
    }

    @Test
    public void testReset() {
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
        action.reset();
        assertFalse(action.isExecuted());
        action.execute(state);
        assertTrue(action.isExecuted());
    }

    @Test
    public void testEquals() {
        assertTrue(action.equals(action));
        assertFalse(action.equals(null));
        assertFalse(action.equals(new Object()));
    }

    @Test
    public void testToString() {
        assertTrue(action.toString().equals("Send Dynamic Client Key Exchange Action: (not executed)\n\tMessages:\n"));
    }

    @Test
    public void testToCompactString() {
        assertTrue(action.toCompactString().equals("SendDynamicClientKeyExchangeAction [client] (no messages set)"));
    }
}