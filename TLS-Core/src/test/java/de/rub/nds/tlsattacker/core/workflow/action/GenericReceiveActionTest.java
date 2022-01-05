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
import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.AlertLevel;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class GenericReceiveActionTest {

    private GenericReceiveAction action;
    private State state;
    private TlsContext tlsContext;
    private AlertMessage alert;

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
        InvalidAlgorithmParameterException {
        alert = new AlertMessage(Config.createConfig());
        alert.setConfig(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR);
        alert.setDescription(AlertDescription.DECODE_ERROR.getValue());
        alert.setLevel(AlertLevel.FATAL.getValue());
        action = new GenericReceiveAction();

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(trace);

        tlsContext = state.getTlsContext();
        tlsContext.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        tlsContext.setRecordLayer(new TlsRecordLayer(tlsContext));
    }

    /**
     * Test of execute method, of class GenericReceiveAction.
     */
    @Test
    public void testExecute() throws Exception {
        ((FakeTransportHandler) tlsContext.getTransportHandler())
            .setFetchableByte(new byte[] { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50 });
        action.execute(state);
        assertTrue(action.executedAsPlanned());
        assertTrue(action.isExecuted());
        assertEquals(action.getReceivedMessages().get(0), alert);
    }

    /**
     * Test of executedAsPlanned method, of class GenericReceiveAction.
     */
    @Test
    public void testExecutedAsPlanned() {
        assertFalse(action.executedAsPlanned());
        action.execute(state);
        assertTrue(action.executedAsPlanned());
    }

    /**
     * Test of reset method, of class GenericReceiveAction.
     */
    @Test
    public void testReset() {
        action.reset();
        assertTrue(action.messages.isEmpty());
        assertTrue(action.records.isEmpty());
        assertTrue(action.fragments.isEmpty());
        assertFalse(action.isExecuted());
    }
}
