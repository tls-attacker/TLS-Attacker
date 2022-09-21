/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

public class ReceiveAsciiActionTest extends AbstractActionTest<ReceiveAsciiAction> {

    private final TlsContext context;

    public ReceiveAsciiActionTest() {
        super(new ReceiveAsciiAction("STARTTLS", "US-ASCII"), ReceiveAsciiAction.class);
        context = state.getTlsContext();
        context.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    /**
     * Test of execute method, of class ReceiveAsciiAction.
     */
    @Test
    @Override
    public void testExecute() throws Exception {
        ((FakeTransportHandler) context.getTransportHandler())
            .setFetchableByte("STARTTLS".getBytes(StandardCharsets.US_ASCII));
        super.testExecute();
    }
}
