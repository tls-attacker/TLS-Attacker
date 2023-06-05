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

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class GenericReceiveAsciiActionTest extends AbstractActionTest<GenericReceiveAsciiAction> {

    private final TlsContext context;

    private final byte[] asciiToCheck =
            new byte[] {
                0x15, 0x03, 0x02, 0x01, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c,
                0x64, 0x21
            };

    public GenericReceiveAsciiActionTest() {
        super(new GenericReceiveAsciiAction("US-ASCII"), GenericReceiveAsciiAction.class);
        context = state.getTlsContext();
        context.setTransportHandler(new FakeTransportHandler(ConnectionEndType.CLIENT));
    }

    /** Test of execute method, of class GenericReceiveAsciiAction. */
    @Test
    @Override
    @Disabled("ASCI Actions are notfully implemented for layer system")
    public void testExecute() throws Exception {
        ((FakeTransportHandler) context.getTransportHandler()).setFetchableByte(asciiToCheck);
        super.testExecute();
        assertEquals(new String(asciiToCheck, StandardCharsets.US_ASCII), action.getAsciiText());
    }

    @Test
    @Disabled("ASCI Actions are notfully implemented for layer system")
    public void testExecuteOnUnknownEncoding() {
        ((FakeTransportHandler) context.getTransportHandler()).setFetchableByte(asciiToCheck);
        GenericReceiveAsciiAction action = new GenericReceiveAsciiAction("DefinitelyNotAnEncoding");
        action.execute(state);
        assertFalse(action.isExecuted());
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
