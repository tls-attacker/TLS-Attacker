/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

public class GenericReceiveAsciiActionTest {

    private State state;
    private TlsContext tlsContext;
    private byte[] asciiToCheck;

    private GenericReceiveAsciiAction action;
    private GenericReceiveAsciiAction actionException;

    @Before
    public void setUp() {
        action = new GenericReceiveAsciiAction("US-ASCII");
        actionException = new GenericReceiveAsciiAction("IOExceptionTest");
        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(trace);

        tlsContext = state.getTlsContext();
        tlsContext.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
        asciiToCheck = new byte[] { 0x15, 0x03, 0x02, 0x01, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
            0x64, 0x21 };
    }

    /**
     * Test of execute method, of class GenericReceiveAsciiAction.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testExecute() throws Exception {
        ((FakeTransportHandler) tlsContext.getTransportHandler()).setFetchableByte(asciiToCheck);

        action.execute(state);
        assertEquals(new String(asciiToCheck, "US-ASCII"), action.getAsciiText());
        assertTrue(action.isExecuted());

        actionException.execute(state);
        assertFalse(actionException.isExecuted());
    }

    /**
     * Test of WorkflowExecutionException of execute method, of class GenericReceiveAsciiAction.
     */
    @Test(expected = WorkflowExecutionException.class)
    public void testExecuteWorkflowExecutionException() {
        action.execute(state);
        action.execute(state);
    }

    /**
     * Test of reset method, of class GenericReceiveAsciiAction.
     */
    @Test
    public void testReset() {
        action.reset();
        assertFalse(action.isExecuted());
    }

    /**
     * Test of executedAsPlanned method, of class GenericReceiveAsciiAction.
     */
    @Test
    public void testExecutedAsPlanned() {
        assertFalse(action.executedAsPlanned());
        action.execute(state);
        assertTrue(action.executedAsPlanned());
    }
}
