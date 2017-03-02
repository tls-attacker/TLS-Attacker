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
    public void testPrepareMessageReadsConfig() {
        AlertHandler handler = new AlertHandler(new TlsContext());
        AlertMessage message = new AlertMessage(new TlsConfig());
        message.setConfig(AlertLevel.FATAL, AlertDescription.UNKNOWN_CA);
        
        byte[] result = handler.prepareMessage(message);
        assertEquals(AlertLevel.FATAL.getValue(), result[0]);
        assertEquals(AlertDescription.UNKNOWN_CA.getValue(), result[1]);
    }
}
