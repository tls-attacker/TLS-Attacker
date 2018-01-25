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
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class ReceiveAsciiActionTest {

    private State state;
    private TlsContext tlsContext;

    private ReceiveAsciiAction action;

    @Before
    public void setUp() {
        action = new ReceiveAsciiAction();

        WorkflowTrace trace = new WorkflowTrace();
        trace.addTlsAction(action);
        state = new State(trace);

        tlsContext = state.getTlsContext();
        tlsContext.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    /**
     * Test of execute method, of class ReceiveAsciiAction.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testReceiveAsciiAction() throws Exception {
        ((FakeTransportHandler) tlsContext.getTransportHandler())
                .setFetchableByte(new byte[] { 0x15, 0x03, 0x02, 0x01 });

        action.execute(state);
        assertTrue(action.isExecuted());
    }
}
