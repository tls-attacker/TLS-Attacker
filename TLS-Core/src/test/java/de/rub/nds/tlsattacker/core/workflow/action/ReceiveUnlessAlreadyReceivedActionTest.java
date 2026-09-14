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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class ReceiveUnlessAlreadyReceivedActionTest
        extends AbstractActionTest<ReceiveUnlessAlreadyReceivedAction> {

    /** One application data record with two bytes of payload. */
    private static final byte[] APPLICATION_RECORD = {0x17, 0x03, 0x03, 0x00, 0x02, 0x41, 0x42};

    public ReceiveUnlessAlreadyReceivedActionTest() {
        super(
                new ReceiveUnlessAlreadyReceivedAction(new ApplicationMessage()),
                ReceiveUnlessAlreadyReceivedAction.class);
        state.getTlsContext()
                .setTransportHandler(new FakeTcpTransportHandler(ConnectionEndType.CLIENT));
    }

    /** The fake transport of the current state; recreateState swaps the state out. */
    private FakeTcpTransportHandler transport() {
        return (FakeTcpTransportHandler) state.getTlsContext().getTransportHandler();
    }

    /** With nothing before it in the trace, the action receives like a plain receive. */
    @Test
    @Override
    public void testExecute() throws Exception {
        transport().setFetchableByte(APPLICATION_RECORD);
        super.testExecute();
        assertFalse(action.isSkipped());
        assertEquals(1, action.getReceivedMessages().size());
        assertEquals(ApplicationMessage.class, action.getReceivedMessages().get(0).getClass());
    }

    @Test
    @Override
    public void testReset() {
        transport().setFetchableByte(APPLICATION_RECORD);
        super.testReset();
    }

    /**
     * When the receive before it already took the expected message, the action does not touch the
     * transport and still counts as executed as planned.
     */
    @Test
    public void testSkipsWhenPreviousReceiveTookTheMessage() {
        ReceiveAction previous = new ReceiveAction(new ApplicationMessage());
        trace = new WorkflowTrace();
        trace.addTlsAction(previous);
        trace.addTlsAction(action);
        recreateState();

        transport().setFetchableByte(APPLICATION_RECORD);
        previous.execute(state);
        assertTrue(previous.executedAsPlanned());

        action.execute(state);
        assertTrue(action.isExecuted());
        assertTrue(action.isSkipped());
        assertTrue(action.executedAsPlanned());
        assertTrue(action.getReceivedMessages().isEmpty());
    }

    /** A previous receive that took something else does not satisfy the action. */
    @Test
    public void testReceivesWhenPreviousReceiveTookSomethingElse() {
        ReceiveAction previous = new ReceiveAction(new FinishedMessage());
        trace = new WorkflowTrace();
        trace.addTlsAction(previous);
        trace.addTlsAction(action);
        recreateState();

        // The previous receive finds no Finished and comes up empty.
        previous.execute(state);
        assertFalse(previous.executedAsPlanned());

        transport().setFetchableByte(APPLICATION_RECORD);
        action.execute(state);
        assertFalse(action.isSkipped());
        assertTrue(action.executedAsPlanned());
        assertEquals(1, action.getReceivedMessages().size());
    }

    /** A connection reset between the two receives ends the search. */
    @Test
    public void testDoesNotLookPastAConnectionReset() {
        ReceiveAction previous = new ReceiveAction(new ApplicationMessage());
        trace = new WorkflowTrace();
        trace.addTlsAction(previous);
        trace.addTlsAction(new ResetConnectionAction());
        trace.addTlsAction(action);
        recreateState();

        transport().setFetchableByte(APPLICATION_RECORD);
        previous.execute(state);
        assertTrue(previous.executedAsPlanned());

        transport().setFetchableByte(APPLICATION_RECORD);
        action.execute(state);
        assertFalse(action.isSkipped());
        assertEquals(1, action.getReceivedMessages().size());
    }

    private void recreateState() {
        state = new de.rub.nds.tlsattacker.core.state.State(config, trace);
        state.getTlsContext()
                .setTransportHandler(new FakeTcpTransportHandler(ConnectionEndType.CLIENT));
    }
}
