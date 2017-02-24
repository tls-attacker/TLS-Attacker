/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.alert;

import de.rub.nds.tlsattacker.tls.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.tls.protocol.handler.AlertHandler;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.workflow.TlsConfig;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 * 
 * @author Juraj Somorovsky - juraj.somorovsky@rub.de
 */
public class AlertHandlerTest {

    /**
     * Test of prepareMessageAction method, of class AlertHandler.
     */
    @Test
    public void testPrepareMessageAction() {
        AlertHandler handler = new AlertHandler(new TlsContext());
        AlertMessage message = new AlertMessage(new TlsConfig());
        message.setConfig(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA);
        handler.setProtocolMessage(message);
        byte[] result = handler.prepareMessageAction();
        assertEquals(AlertLevel.FATAL.getValue(), result[0]);
        assertEquals(AlertDescription.UNKNOWN_CA.getValue(), result[1]);
    }

    /**
     * Test of parseMessageAction method, of class AlertHandler.
     */
    @Test
    public void testParseMessageAction() {
        AlertHandler handler = new AlertHandler(new TlsContext());
        handler.setProtocolMessage(new AlertMessage(new TlsConfig()));
        byte[] message = { 3, 3 };
        int pointer = handler.parseMessageAction(message, 0);
        assertEquals(2, pointer);
        assertEquals(3, handler.getProtocolMessage().getLevel().getValue().byteValue());
        assertEquals(3, handler.getProtocolMessage().getDescription().getValue().byteValue());
    }

}
