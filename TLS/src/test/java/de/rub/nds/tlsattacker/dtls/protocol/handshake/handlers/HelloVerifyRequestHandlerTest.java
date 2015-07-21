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
package de.rub.nds.tlsattacker.dtls.protocol.handshake.handlers;

import de.rub.nds.tlsattacker.dtls.protocol.handshake.messagefields.HandshakeMessageDtlsFields;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.messages.ClientHelloMessage;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.messages.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.tls.protocol.handshake.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.protocol.handshake.messages.HandshakeMessageFactory;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import org.junit.Test;

/**
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 */
public class HelloVerifyRequestHandlerTest {

    ProtocolMessageHandler handler;

    TlsContext tlsContext = new TlsContext();

    HandshakeMessageFactory hmFactory = new HandshakeMessageFactory(ProtocolVersion.DTLS12);

    byte[] helloVerifyRequestMessageBytes = ArrayConverter
	    .hexStringToByteArray("030000070005000000000007FEFD0448EA9A2C0300000B000600000000000BFEFD08112210F47DE981150300010100"
		    + "07000000000101FEFDFEF3BAC3A86C53A2D40FF77E606DA78BF037435FDBBB656FE2C01F4145169F90B75B6E2DB9309EE4EB9EC45B"
		    + "DBCC22C391DF6D91CC5D5EE91C3802C089B0752FD7514243719A7583789AFE38A600FD7979C5FFCE81FEDD6062A707E95920D99734"
		    + "EE5F96E1F9AA9B09F794F3C74EF3008C3131060B31C530B68AE5E684A51AA4823C0F773B00D5B99BBE0F5AFFA3A0095FB5705866DF"
		    + "E7FD24D2ECA01CD84F0E6BFC3E05CC36E8CA242E931EE144F972740FE0065A5F49ADE4D4609ED6523F45437C34DAC38F82553398B0"
		    + "AC3E7C90194B802819AD2DB028231D259598E85CD260FA7D72BD3DDAB50703693A9196DD0628811F8705089B1CF469462EF83213");

    public HelloVerifyRequestHandlerTest() {
	tlsContext.setProtocolVersion(ProtocolVersion.DTLS12);
    }

    /**
     * Test of prepareMessageAction method, of class ClientHelloHandler.
     */
    @Test
    public void testPrepareMessage() {
	handler = new HelloVerifyRequestHandler(tlsContext);
	handler.setProtocolMessage(hmFactory.createHandshakeMessage(HelloVerifyRequestMessage.class));
	HelloVerifyRequestMessage message = (HelloVerifyRequestMessage) handler.getProtocolMessage();
        
	message.setCookie(ArrayConverter.hexStringToByteArray("112233"));
	message.setCookieLength((byte) 3);

	HandshakeMessageDtlsFields messageFields = (HandshakeMessageDtlsFields) message.getMessageFields();

	messageFields.setMessageSeq(500);

	byte[] returned = handler.prepareMessage();
	byte[] expected = ArrayConverter.concatenate(
		new byte[] { HandshakeMessageType.HELLO_VERIFY_REQUEST.getValue() }, new byte[] { 0x00, 0x00, 0x06,
			0x01, (byte) 0xF4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06 }, tlsContext.getProtocolVersion()
			.getValue(), new byte[] { message.getCookieLength().getValue() }, message.getCookie()
			.getValue());

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }

    @Test
    public void testParseMessageAction() {
	handler = new HelloVerifyRequestHandler(tlsContext);

	handler.setProtocolMessage(hmFactory.createHandshakeMessage(HelloVerifyRequestMessage.class));

	int endPointer = 0;
	endPointer = handler.parseMessage(helloVerifyRequestMessageBytes, endPointer);

	HelloVerifyRequestMessage message = (HelloVerifyRequestMessage) handler.getProtocolMessage();

	byte expectedCookieLength = 4;
	byte actualCookieLength = message.getCookieLength().getValue();
	byte[] expectedCookie = ArrayConverter.hexStringToByteArray("48EA9A2C");
	byte[] actualCookie = message.getCookie().getValue();

	HandshakeMessageDtlsFields handshakeMessageFields = (HandshakeMessageDtlsFields) message.getMessageFields();

	assertEquals("Check message type", HandshakeMessageType.HELLO_VERIFY_REQUEST, message.getHandshakeMessageType());
	assertEquals("Message length should be 7 bytes", new Integer(7), handshakeMessageFields.getLength().getValue());
	assertArrayEquals("Check Protocol Version", ProtocolVersion.DTLS12.getValue(), message.getProtocolVersion()
		.getValue());
	assertEquals("Check cookie length", expectedCookieLength, actualCookieLength);
	assertArrayEquals("Check cookie", expectedCookie, actualCookie);
	assertEquals("Check protocol message length pointer", 19, endPointer);

	handler = new HelloVerifyRequestHandler(tlsContext);

	handler.setProtocolMessage(hmFactory.createHandshakeMessage(HelloVerifyRequestMessage.class));

	endPointer = handler.parseMessage(helloVerifyRequestMessageBytes, endPointer);

	message = (HelloVerifyRequestMessage) handler.getProtocolMessage();

	expectedCookieLength = 8;
	actualCookieLength = message.getCookieLength().getValue();
	expectedCookie = ArrayConverter.hexStringToByteArray("112210F47DE98115");
	actualCookie = message.getCookie().getValue();

	handshakeMessageFields = (HandshakeMessageDtlsFields) message.getMessageFields();

	assertEquals("Check message type", HandshakeMessageType.HELLO_VERIFY_REQUEST, message.getHandshakeMessageType());
	assertEquals("Message length should be 11 bytes", new Integer(11), handshakeMessageFields.getLength()
		.getValue());
	assertArrayEquals("Check Protocol Version", ProtocolVersion.DTLS12.getValue(), message.getProtocolVersion()
		.getValue());
	assertEquals("Check cookie length", expectedCookieLength, actualCookieLength);
	assertArrayEquals("Check cookie", expectedCookie, actualCookie);
	assertEquals("Check protocol message length pointer", 42, endPointer);

	handler = new HelloVerifyRequestHandler(tlsContext);

	handler.setProtocolMessage(hmFactory.createHandshakeMessage(HelloVerifyRequestMessage.class));

	endPointer = handler.parseMessage(helloVerifyRequestMessageBytes, endPointer);

	message = (HelloVerifyRequestMessage) handler.getProtocolMessage();

	expectedCookieLength = (byte) 254;
	actualCookieLength = message.getCookieLength().getValue();
	expectedCookie = ArrayConverter
		.hexStringToByteArray("F3BAC3A86C53A2D40FF77E606DA78BF037435FDBBB656FE2C01F4145169F90B75B6E2DB9309EE4EB9EC45BDBCC"
			+ "22C391DF6D91CC5D5EE91C3802C089B0752FD7514243719A7583789AFE38A600FD7979C5FFCE81FEDD6062A707E95920D99734"
			+ "EE5F96E1F9AA9B09F794F3C74EF3008C3131060B31C530B68AE5E684A51AA4823C0F773B00D5B99BBE0F5AFFA3A0095FB57058"
			+ "66DFE7FD24D2ECA01CD84F0E6BFC3E05CC36E8CA242E931EE144F972740FE0065A5F49ADE4D4609ED6523F45437C34DAC38F82"
			+ "553398B0AC3E7C90194B802819AD2DB028231D259598E85CD260FA7D72BD3DDAB50703693A9196DD0628811F8705089B1CF469"
			+ "462EF83213");
	actualCookie = message.getCookie().getValue();

	handshakeMessageFields = (HandshakeMessageDtlsFields) message.getMessageFields();

	assertEquals("Check message type", HandshakeMessageType.HELLO_VERIFY_REQUEST, message.getHandshakeMessageType());
	assertEquals("Message length should be 257 bytes", new Integer(257), handshakeMessageFields.getLength()
		.getValue());
	assertArrayEquals("Check Protocol Version", ProtocolVersion.DTLS12.getValue(), message.getProtocolVersion()
		.getValue());
	assertEquals("Check cookie length", expectedCookieLength, actualCookieLength);
	assertArrayEquals("Check cookie", expectedCookie, actualCookie);
	assertEquals("Check protocol message length pointer", 311, endPointer);
    }

}
