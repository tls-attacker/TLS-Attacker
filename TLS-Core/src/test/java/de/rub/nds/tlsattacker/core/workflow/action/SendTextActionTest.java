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

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeTcpTransportHandler;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import jakarta.xml.bind.JAXBException;
import java.io.IOException;
import javax.xml.stream.XMLStreamException;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class SendTextActionTest extends AbstractActionTest<SendTextAction> {

    public SendTextActionTest() {
        super(new SendTextAction("STARTTLS", "US-ASCII"), SendTextAction.class);
        TlsContext context = state.getTlsContext();
        context.setTransportHandler(new FakeTcpTransportHandler(ConnectionEndType.CLIENT));
    }

    /** Test of getText method, of class SendTextAction. */
    @Test
    public void testGetText() {
        assertEquals("STARTTLS", action.getText());
    }

    @Test
    @Override
    @Disabled("Text Actions are not fully implemented for layer system")
    public void testExecute() throws Exception {
        super.testExecute();
    }

    @Override
    @Disabled("Text Actions are not fully implemented for layer system")
    public void testReset() {}

    @Override
    @Disabled("Text Actions are not fully implemented for layer system")
    public void testDoubleExecuteThrowsActionExecutionException() {}

    @Override
    @Disabled("Text Actions are not fully implemented for layer system")
    public void testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject()
            throws JAXBException, IOException, XMLStreamException {
        super.testMarshalingAndUnmarshalingFilledObjectYieldsEqualObject();
    }

    @Override
    @Disabled("Text Actions are not fully implemented for layer system")
    public void testMarshalingAndUnmarshalingEmptyObjectYieldsEqualObject()
            throws JAXBException, IOException, XMLStreamException {
        super.testMarshalingAndUnmarshalingEmptyObjectYieldsEqualObject();
    }

    @Override
    @Disabled("Text Actions are not fully implemented for layer system")
    public void testMarshalingEmptyActionYieldsMinimalOutput() throws JAXBException, IOException {
        super.testMarshalingEmptyActionYieldsMinimalOutput();
    }
}
