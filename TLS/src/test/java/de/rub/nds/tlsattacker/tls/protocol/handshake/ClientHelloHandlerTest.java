/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.dtls.protocol.handshake.ClientHelloDtlsMessage;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.protocol.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.HeartbeatExtensionMessage;
import de.rub.nds.tlsattacker.tls.protocol.extension.EllipticCurvesExtensionMessage;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Florian Pfützenreuter <florian.pfuetzenreuter@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ClientHelloHandlerTest {

    static byte[] clientHelloWithoutExtensionBytes = ArrayConverter
	    .hexStringToByteArray("01000059030336CCE3E132A0C5B5DE2C0560B4FF7F6CDF7AE226120E4A99C07E2D9B68B275BB20FA6F8E9770106ACE8ACAB73E18B5D867CAF8AF7E206EF496F23A206A379FC7110012C02BC02FC00AC009C013C014002F0035000A0100");

    static byte[] clientHelloWithHeartbeatandEllipticCurvesBytes = ArrayConverter
	    .hexStringToByteArray("0100003A0303561EAC1C71D111AB0186813D11808C3EEA236E37C0110A75B929D6E0A3F53F42000002C0300100000F000F000101000A00060004000F0001");

    static byte[] clientHelloWithHeartbeatBytes = ArrayConverter
	    .hexStringToByteArray("010000300303561EAC1C71D111AB0186813D11808C3EEA236E37C0110A75B929D6E0A3F53F42000002C03001000005000F000101");

    // DTLS clientHello with the dtls handshake fields (messageSeq,
    // fragmentOffset and fragmentLength) already stripped out.
    // Thus, only the cookie remains.
    static byte[] dtlsClientHelloWithoutExtensionBytes = ArrayConverter
	    .hexStringToByteArray("0100005eFEFD36CCE3E132A0C5B5DE2C0560B4FF7F6CDF7AE226120E4A99C07E2D9B68B275BB20FA6F8E9770106ACE8ACAB73E18B5D867CAF8AF7E206EF496F23A206A379FC711061122334455660012C02BC02FC00AC009C013C014002F0035000A0100");

    static byte[] cookie = ArrayConverter.hexStringToByteArray("1122334455667788");

    ClientHelloHandler handler;
    ClientHelloHandler dtlshandler;

    TlsContext tlsContext = new TlsContext();
    TlsContext dtlsContext = new TlsContext();

    public ClientHelloHandlerTest() {
	tlsContext.setProtocolVersion(ProtocolVersion.TLS12);
	handler = new ClientHelloHandler(tlsContext);
	dtlsContext.setDtlsHandshakeCookie(cookie);
	dtlsContext.setProtocolVersion(ProtocolVersion.DTLS12);
	dtlshandler = new ClientHelloHandler(dtlsContext);

    }

    /**
     * Test of prepareMessageAction method, of class ClientHelloHandler.
     */
    @Test
    public void testPrepareMessage() {
	dtlshandler.setProtocolMessage(new ClientHelloDtlsMessage());

	ClientHelloDtlsMessage message = (ClientHelloDtlsMessage) dtlshandler.getProtocolMessage();

	List<CipherSuite> cipherSuites = new ArrayList();
	cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
	message.setSupportedCipherSuites(cipherSuites);

	List<CompressionMethod> compressionMethods = new ArrayList();
	compressionMethods.add(CompressionMethod.NULL);
	message.setSupportedCompressionMethods(compressionMethods);

	byte[] returned = dtlshandler.prepareMessageAction();
	byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.CLIENT_HELLO.getValue() },
		new byte[] { 0x00, 0x00, 0x32 }, ProtocolVersion.DTLS12.getValue(), message.getUnixTime().getValue(),
		message.getRandom().getValue(), new byte[] { 0x00, 0x08 }, cookie, new byte[] { 0x00, 0x02 },
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.getByteValue(), new byte[] { 0x01,
			CompressionMethod.NULL.getValue() });

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }

    @Test
    public void testPrepareMessageWithExtensions() {
	handler.setProtocolMessage(new ClientHelloDtlsMessage());

	de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage message = (de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage) handler
		.getProtocolMessage();

	List<CipherSuite> cipherSuites = new ArrayList();
	cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
	message.setSupportedCipherSuites(cipherSuites);

	List<CompressionMethod> compressionMethods = new ArrayList();
	compressionMethods.add(CompressionMethod.NULL);
	message.setSupportedCompressionMethods(compressionMethods);

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

	byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.CLIENT_HELLO.getValue() },
		new byte[] { 0x00, 0x00, 0x3A }, ProtocolVersion.TLS12.getValue(), message.getUnixTime().getValue(),
		message.getRandom().getValue(), ArrayConverter.intToBytes(message.getSessionIdLength().getValue(), 1),
		new byte[] { 0x00, 0x02 }, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.getByteValue(),
		new byte[] { 0x01, CompressionMethod.NULL.getValue() }, new byte[] { 0x00, 0x0F },
		ExtensionType.HEARTBEAT.getValue(),
		new byte[] { 0x00, 0x01, HeartbeatMode.PEER_ALLOWED_TO_SEND.getValue() },
		ExtensionType.ELLIPTIC_CURVES.getValue(), new byte[] { 0x00, 0x06 }, new byte[] { 0x00, 0x04 },
		NamedCurve.SECP160K1.getValue(), NamedCurve.SECT163K1.getValue());

	assertNotNull("Confirm function didn't return 'NULL'", returned);
	assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }

    @Test
    public void testParseMessageAction() {
	dtlshandler.setProtocolMessage(new ClientHelloDtlsMessage());

	int endPointer = dtlshandler.parseMessageAction(dtlsClientHelloWithoutExtensionBytes, 0);
	ClientHelloDtlsMessage message = (ClientHelloDtlsMessage) dtlshandler.getProtocolMessage();

	byte[] expectedRandom = ArrayConverter
		.hexStringToByteArray("36cce3e132a0c5b5de2c0560b4ff7f6cdf7ae226120e4a99c07e2d9b68b275bb");
	byte[] actualRandom = ArrayConverter.concatenate(message.getUnixTime().getValue(), message.getRandom()
		.getValue());
	byte[] expectedSessionID = ArrayConverter
		.hexStringToByteArray("fa6f8e9770106ace8acab73e18b5d867caf8af7e206ef496f23a206a379fc711");
	byte[] actualSessionID = message.getSessionId().getValue();

	byte expectedCookieLength = 6;
	byte actualCookieLength = message.getCookieLength().getValue();
	byte[] expectedCookie = ArrayConverter.hexStringToByteArray("112233445566");
	byte[] actualCookie = message.getCookie().getValue();

	byte[] expectedCipherSuites = ArrayConverter.hexStringToByteArray("c02bc02fc00ac009c013c014002f0035000a");
	byte[] actualCipherSuites = message.getCipherSuites().getValue();

	assertEquals("Check message type", HandshakeMessageType.CLIENT_HELLO, message.getHandshakeMessageType());
	assertEquals("Message length should be 94 bytes", new Integer(94), message.getLength().getValue());
	assertArrayEquals("Check Protocol Version", ProtocolVersion.DTLS12.getValue(), message.getProtocolVersion()
		.getValue());
	assertArrayEquals("Check random", expectedRandom, actualRandom);
	assertEquals("Check session_id length", new Integer(32), message.getSessionIdLength().getValue());
	assertArrayEquals("Check session_id", expectedSessionID, actualSessionID);

	assertEquals("Check cookie length", expectedCookieLength, actualCookieLength);
	assertArrayEquals("Check cookie", expectedCookie, actualCookie);

	assertEquals("Check cipher_suites length", new Integer(18), message.getCipherSuiteLength().getValue());
	assertArrayEquals("Check cipher_suites", expectedCipherSuites, actualCipherSuites);
	assertEquals("Check compressions length", new Integer(1), message.getCompressionLength().getValue());
	assertArrayEquals("Check compressions", new byte[] { 0x00 }, message.getCompressions().getValue());
	assertEquals("Check protocol message length pointer", dtlsClientHelloWithoutExtensionBytes.length, endPointer);
    }

    /**
     * Test of parseMessageActionwithExtensions method, of class
     * ClientHelloHandler.
     */
    @Test
    public void testParseMessageWithExtensions() {
	handler.initializeProtocolMessage();

	int endPointer = handler.parseMessageAction(clientHelloWithHeartbeatBytes, 0);
	de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage message = (de.rub.nds.tlsattacker.tls.protocol.handshake.ClientHelloMessage) handler
		.getProtocolMessage();

	assertEquals("Message type must be ClientHello", HandshakeMessageType.CLIENT_HELLO,
		message.getHandshakeMessageType());
	assertEquals("Message length must be 48", new Integer(48), message.getLength().getValue());
	assertEquals("Protocol version must be TLS 1.2", ProtocolVersion.TLS12, tlsContext.getProtocolVersion());
	assertEquals("Client Session ID Length", new Integer(0), message.getSessionIdLength().getValue());
	assertArrayEquals(
		"Client Random",
		ArrayConverter.hexStringToByteArray("561EAC1C71D111AB0186813D11808C3EEA236E37C0110A75B929D6E0A3F53F42"),
		tlsContext.getClientRandom());
	assertEquals("Cipersuite Length", new Integer(2), message.getCipherSuiteLength().getValue());
	assertArrayEquals("Ciphersuite must be TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.getByteValue(), message.getCipherSuites().getValue());
	assertEquals("Compression Length", new Integer(1), message.getCompressionLength().getValue());
	assertArrayEquals("Compression must be null", CompressionMethod.NULL.getArrayValue(), message.getCompressions()
		.getValue());
	assertTrue("Extension must be Heartbeat", message.containsExtension(ExtensionType.HEARTBEAT));

	assertEquals("The pointer has to return the length of this message + starting position",
		clientHelloWithHeartbeatBytes.length, endPointer);
    }
}
