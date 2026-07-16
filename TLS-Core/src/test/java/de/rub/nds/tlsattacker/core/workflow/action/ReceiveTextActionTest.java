/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

public class ReceiveTextActionTest extends AbstractActionTest<ReceiveTextAction> {

    private final TlsContext context;

    public ReceiveTextActionTest() {
        super(new ReceiveTextAction("STARTTLS", "US-ASCII"), ReceiveTextAction.class);
        context = state.getTlsContext();
        context.setTransportHandler(new FakeTcpTransportHandler(ConnectionEndType.CLIENT));
    }

    /** Test of execute method, of class ReceiveTextAction. */
    @Test
    @Override
    public void testExecute() throws Exception {
        ((FakeTcpTransportHandler) context.getTransportHandler())
                .setFetchableByte("STARTTLS".getBytes(StandardCharsets.US_ASCII));
        super.testExecute();
    }

    @Override
    protected void createWorkflowTraceAndState() {
        state = new State();
    }
}
