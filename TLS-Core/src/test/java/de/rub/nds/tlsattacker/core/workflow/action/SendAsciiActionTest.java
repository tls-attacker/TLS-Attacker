/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class SendAsciiActionTest {

    private State state;
    private TlsContext tlsContext;
    private final String expString = "STARTTLS";
    private SendAsciiAction action;

    @Before
    public void setUp() {
        action = new SendAsciiAction(expString, "US-ASCII");

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(trace);

        tlsContext = state.getTlsContext();
        tlsContext.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));

    }

    /**
     * Test of execute method, of class SendAsciiAction.
     *
     * @throws java.io.IOException
     */
    @Test
    public void testExecute() throws IOException {
        action.execute(state);
        assertTrue(action.isExecuted());
    }

    /**
     * Test of WorkflowExecutionException of execute method, of class
     * SendAsciiAction.
     *
     * @throws java.io.IOException
     */
    @Test(expected = WorkflowExecutionException.class)
    public void testExecuteWorkflowExecutionException() throws IOException {
        action.execute(state);
        action.execute(state);
    }

    /**
     * Test of reset method, of class SendAsciiAcion.
     */
    @Test
    public void testReset() {
        action.reset();
        assertFalse(action.isExecuted());
    }

    /**
     * Test of executedAsPlanned method, of class SendAsciiAcion.
     */
    @Test
    public void testExecutedAsPlanned() {
        assertFalse(action.executedAsPlanned());
        action.execute(state);
        // TODO add assertTrue after execute
    }

    /**
     * Test of getAsciiString method, of class SendAsciiAcion.
     */
    @Test
    public void testGetAsciiString() {
        assertEquals(expString, action.getAsciiText());
    }
}
