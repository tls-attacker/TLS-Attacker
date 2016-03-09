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
package de.rub.nds.tlsattacker.tls.protocol.application.handlers;

import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import de.rub.nds.tlsattacker.tls.protocol.application.messages.ApplicationMessage;
import static org.junit.Assert.assertArrayEquals;

/**
 * 
 * @author Robert Merget
 */
public class ApplicationHandlerTest {
    /**
     * Test of parseMessageAction method, of class ApplicationHandler.
     */
    @Test
    public void testParseMessageAction() {
	ApplicationHandler handler = new ApplicationHandler(new TlsContext());
	handler.setProtocolMessage(new ApplicationMessage());
	byte[] message = { 1, 2, 3, 4 };
	int pointer = handler.parseMessageAction(message, 0);
	assertEquals(message.length, pointer);
	assertArrayEquals(message, handler.getProtocolMessage().getData().getOriginalValue());

    }
}
