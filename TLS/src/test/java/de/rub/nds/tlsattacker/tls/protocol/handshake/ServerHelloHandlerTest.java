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

import de.rub.nds.tlsattacker.tls.protocol.handshake.HandshakeMessageFields;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloHandler;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.handshake.ServerHelloMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ServerHelloHandlerTest {

    static byte[] serverKeyExchangeWithoutExtensionBytes = ArrayConverter
	    .hexStringToByteArray("02000046030354cf6dcf922b63e8cb6af7527c6520f727d526b178ecf3218027ccf8bb125d5720682200"
		    + "00ba8c0f774ba7de9f5cdbfdf364d81e28f6f68502cd596792769be4c0c01300");

    static byte[] serverKeyExchangeWithHeartbeatBytes = ArrayConverter
	    .hexStringToByteArray("0200004D030354cf6dcf922b63e8cb6af7527c6520f727d526b178ecf3218027ccf8bb125d5720682200"
		    + "00ba8c0f774ba7de9f5cdbfdf364d81e28f6f68502cd596792769be4c0c013000005000F000101");

    ServerHelloHandler handler;

    TlsContext tlsContext;

    public ServerHelloHandlerTest() {
	tlsContext = new TlsContext();
	tlsContext.setProtocolVersion(ProtocolVersion.TLS12);
	handler = new ServerHelloHandler(tlsContext);
    }

    /**
     * Test of parseMessageAction method, of class ServerHelloHandler.
     */
    @Test
    public void testParseMessage() {
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(serverKeyExchangeWithoutExtensionBytes, 0);
	ServerHelloMessage message = (ServerHelloMessage) handler.getProtocolMessage();
	HandshakeMessageFields handshakeMessageFields = message.getMessageFields();

	assertEquals("Message type must be ServerHello", HandshakeMessageType.SERVER_HELLO,
		message.getHandshakeMessageType());
	assertEquals("Message length must be 70", new Integer(70), handshakeMessageFields.getLength().getValue());
	assertEquals("Protocol version must be TLS 1.2", ProtocolVersion.TLS12, tlsContext.getProtocolVersion());
	assertArrayEquals(
		"Server Session ID",
		ArrayConverter.hexStringToByteArray("68220000ba8c0f774ba7de9f5cdbfdf364d81e28f6f68502cd596792769be4c0"),
		message.getSessionId().getValue());
	assertArrayEquals(
		"Server Random",
		ArrayConverter.hexStringToByteArray("54cf6dcf922b63e8cb6af7527c6520f727d526b178ecf3218027ccf8bb125d57"),
		tlsContext.getServerRandom());
	assertEquals("Ciphersuite must be TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tlsContext.getSelectedCipherSuite());
	assertEquals("Compression must be null", CompressionMethod.NULL, tlsContext.getCompressionMethod());

	assertEquals("The pointer has to return the length of this message + starting position",
		serverKeyExchangeWithoutExtensionBytes.length, endPointer);
    }

    /**
     * Test of parseMessageAction method, of class ServerHelloHandler.
     */
    @Test
    public void testParseMessageWithExtensions() {
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(serverKeyExchangeWithHeartbeatBytes, 0);
	ServerHelloMessage message = (ServerHelloMessage) handler.getProtocolMessage();
	HandshakeMessageFields handshakeMessageFields = message.getMessageFields();

	assertEquals("Message type must be ServerHello", HandshakeMessageType.SERVER_HELLO,
		message.getHandshakeMessageType());
	assertEquals("Message length must be 77", new Integer(77), handshakeMessageFields.getLength().getValue());
	assertEquals("Protocol version must be TLS 1.2", ProtocolVersion.TLS12, tlsContext.getProtocolVersion());
	assertArrayEquals(
		"Server Session ID",
		ArrayConverter.hexStringToByteArray("68220000ba8c0f774ba7de9f5cdbfdf364d81e28f6f68502cd596792769be4c0"),
		message.getSessionId().getValue());
	assertArrayEquals(
		"Server Random",
		ArrayConverter.hexStringToByteArray("54cf6dcf922b63e8cb6af7527c6520f727d526b178ecf3218027ccf8bb125d57"),
		tlsContext.getServerRandom());
	assertEquals("Ciphersuite must be TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tlsContext.getSelectedCipherSuite());
	assertEquals("Compression must be null", CompressionMethod.NULL, tlsContext.getCompressionMethod());
	assertTrue("Extension must be Heartbeat", message.containsExtension(ExtensionType.HEARTBEAT));

	assertEquals("The pointer has to return the length of this message + starting position",
		serverKeyExchangeWithHeartbeatBytes.length, endPointer);
    }

    /**
     * Test of prepareMessageAction method, of class ServerHelloHandler.
     */
    @Test
    public void testPrepareMessage() {
	handler.setProtocolMessage(new ServerHelloMessage());

	ServerHelloMessage message = (ServerHelloMessage) handler.getProtocolMessage();

	tlsContext.setCompressionMethod(CompressionMethod.NULL);

	byte[] returned = handler.prepareMessageAction();
	byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.SERVER_HELLO.getValue() },
		new byte[] { 0x00, 0x00, 0x46 }, ProtocolVersion.TLS12.getValue(), message.getUnixTime().getValue(),
		message.getRandom().getValue(), new byte[] { 0x20 }, message.getSessionId().getValue(),
		CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA.getValue(),
		new byte[] { CompressionMethod.NULL.getValue() });

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }

    /**
     * Test of prepareMessageAction method with Extensions, of class
     * ServerHelloHandler.
     */
    @Test
    public void testPrepareMessageWithExtensions() {
	handler.setProtocolMessage(new ServerHelloMessage());

	ServerHelloMessage message = (ServerHelloMessage) handler.getProtocolMessage();

	tlsContext.setCompressionMethod(CompressionMethod.NULL);

	HeartbeatExtensionMessage heart;
	heart = new HeartbeatExtensionMessage();
	heart.setHeartbeatModeConfig(HeartbeatMode.PEER_ALLOWED_TO_SEND);

	EllipticCurvesExtensionMessage ecc;
	ecc = new EllipticCurvesExtensionMessage();
	List<NamedCurve> curve = new ArrayList();
	curve.add(NamedCurve.SECP160K1);
	curve.add(NamedCurve.SECT163K1);
	ecc.setSupportedCurvesConfig(curve);

	List<ExtensionMessage> extensions = new ArrayList();
	extensions.add(heart);
	extensions.add(ecc);
	message.setExtensions(extensions);

	byte[] returned = handler.prepareMessageAction();
	byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.SERVER_HELLO.getValue() },
		new byte[] { 0x00, 0x00, 0x57 }, ProtocolVersion.TLS12.getValue(), message.getUnixTime().getValue(),
		message.getRandom().getValue(), new byte[] { 0x20 }, message.getSessionId().getValue(),
		CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA.getValue(),
		new byte[] { CompressionMethod.NULL.getValue() }, new byte[] { 0x00, 0x0F },
		ExtensionType.HEARTBEAT.getValue(),
		new byte[] { 0x00, 0x01, HeartbeatMode.PEER_ALLOWED_TO_SEND.getValue() },
		ExtensionType.ELLIPTIC_CURVES.getValue(), new byte[] { 0x00, 0x06 }, new byte[] { 0x00, 0x04 },
		NamedCurve.SECP160K1.getValue(), NamedCurve.SECT163K1.getValue());

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }

}
