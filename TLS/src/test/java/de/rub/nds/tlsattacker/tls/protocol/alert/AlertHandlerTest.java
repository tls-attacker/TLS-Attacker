/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security, Ruhr University
 * Bochum (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.alert;

import de.rub.nds.tlsattacker.tls.protocol.alert.AlertHandler;
import de.rub.nds.tlsattacker.tls.constants.AlertDescription;
import de.rub.nds.tlsattacker.tls.constants.AlertLevel;
import de.rub.nds.tlsattacker.tls.protocol.alert.AlertMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import org.junit.Test;
import static org.junit.Assert.*;

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
	AlertMessage message = new AlertMessage();
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
	handler.setProtocolMessage(new AlertMessage());
	byte[] message = { 3, 3 };
	int pointer = handler.parseMessageAction(message, 0);
	assertEquals(2, pointer);
	assertEquals(3, handler.getProtocolMessage().getLevel().getValue().byteValue());
	assertEquals(3, handler.getProtocolMessage().getDescription().getValue().byteValue());
    }

}
