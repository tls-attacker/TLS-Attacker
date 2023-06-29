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
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class ReceiveAsciiActionTest extends AbstractActionTest<ReceiveAsciiAction> {

    private final TlsContext context;

    public ReceiveAsciiActionTest() {
        super(new ReceiveAsciiAction("STARTTLS", "US-ASCII"), ReceiveAsciiAction.class);
        context = state.getTlsContext();
        context.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    /** Test of execute method, of class ReceiveAsciiAction. */
    @Test
    @Override
    @Disabled("ASCI Actions are notfully implemented for layer system")
    public void testExecute() throws Exception {
        ((FakeTransportHandler) context.getTransportHandler())
                .setFetchableByte("STARTTLS".getBytes(StandardCharsets.US_ASCII));
        super.testExecute();
    }

    @Override
    @Disabled("ASCI Actions are notfully implemented for layer system")
    public void testReset() {}

    @Override
    @Disabled("ASCI Actions are notfully implemented for layer system")
    public void testDoubleExecuteThrowsActionExecutionException() {}

    @Override
    protected void createWorkflowTraceAndState() {
        state = new State();
    }

    @Override
    @Disabled("ASCI Actions are notfully implemented for layer system")
    public void testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject() {
        super.testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject();
    }

    @Override
    @Disabled("ASCI Actions are notfully implemented for layer system")
    public void testMarshalingAndUnmarshalingEmptyObjectYieldsEqualObject() {
        super.testMarshalingAndUnmarshalingEmptyObjectYieldsEqualObject();
    }

    @Override
    @Disabled("ASCI Actions are notfully implemented for layer system")
    public void testMarshalingEmptyActionYieldsMinimalOutput() throws JAXBException, IOException {
        super.testMarshalingEmptyActionYieldsMinimalOutput();
    }
}
