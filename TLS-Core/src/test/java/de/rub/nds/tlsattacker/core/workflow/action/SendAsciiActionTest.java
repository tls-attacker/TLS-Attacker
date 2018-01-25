/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.io.IOException;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class SendAsciiActionTest {
    private State state;
    private TlsContext tlsContext;

    private SendAsciiAction action;

    @Before
    public void setUp() {
        action = new SendAsciiAction("STARTTLS");

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

}
