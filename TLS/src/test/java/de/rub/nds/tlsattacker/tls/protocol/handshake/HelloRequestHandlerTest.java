/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS.
 *
 * Copyright (C) 2015 Chair for Network and Data Security,
 *                    Ruhr University Bochum
 *                    (juraj.somorovsky@rub.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Philip Riese <philip.riese@rub.de>
 */
public class HelloRequestHandlerTest {

    private HelloRequestHandler handler;

    public HelloRequestHandlerTest() {
	handler = new HelloRequestHandler(new TlsContext());
    }

    /**
     * Test of prepareMessageAction method, of class HelloRequestHandler.
     */
    @Test
    public void testPrepareMessageAction() {
	handler.setProtocolMessage(new HelloRequestMessage());

	HelloRequestMessage message = (HelloRequestMessage) handler.getProtocolMessage();

	byte[] returned = handler.prepareMessageAction();
	byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.HELLO_REQUEST.getValue() },
		new byte[] { 0x00, 0x00, 0x00 });

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }

    /**
     * Test of parseMessageAction method, of class HelloRequestHandler.
     */
    @Test
    public void testParseMessageAction() {
	byte[] helloRequestMsg = { 0x00, 0x00, 0x00, 0x00 };
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessage(helloRequestMsg, 0);
	HelloRequestMessage message = handler.getProtocolMessage();
	HandshakeMessageFields handshakeMessageFields = message.getMessageFields();

	assertNotNull("Confirm that parseMessage didn't return 'NULL'", endPointer);
	assertEquals("Confirm expected message type: \"HelloRequest\"", HandshakeMessageType.HELLO_REQUEST,
		message.getHandshakeMessageType());
	assertEquals("Confirm expected message length of \"0\"", new Integer(0), handshakeMessageFields.getLength()
		.getValue());
	assertEquals("Confirm the correct value of endPointer representing the " + "actual number of message bytes",
		helloRequestMsg.length, endPointer);
    }

}
