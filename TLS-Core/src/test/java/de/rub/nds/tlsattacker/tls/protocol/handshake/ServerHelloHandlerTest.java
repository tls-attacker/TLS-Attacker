/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake;

import de.rub.nds.tlsattacker.tls.constants.CipherSuite;
import de.rub.nds.tlsattacker.tls.constants.CompressionMethod;
import de.rub.nds.tlsattacker.tls.constants.ExtensionType;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.tls.constants.NamedCurve;
import de.rub.nds.tlsattacker.tls.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.tls.protocol.handshake.handler.ServerHelloHandler;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.junit.Assert;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import org.junit.Test;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
public class ServerHelloHandlerTest {

    static byte[] serverHelloWithoutExtensionBytes = ArrayConverter
            .hexStringToByteArray("02000046030354cf6dcf922b63e8cb6af7527c6520f727d526b178ecf3218027ccf8bb125d5720682200"
                    + "00ba8c0f774ba7de9f5cdbfdf364d81e28f6f68502cd596792769be4c0c01300");

    static byte[] serverHelloWithHeartbeatBytes = ArrayConverter
            .hexStringToByteArray("0200004D030354cf6dcf922b63e8cb6af7527c6520f727d526b178ecf3218027ccf8bb125d5720682200"
                    + "00ba8c0f774ba7de9f5cdbfdf364d81e28f6f68502cd596792769be4c0c013000005000F000101");
    static byte[] serverHelloDTLSnoExtensions = ArrayConverter
            .hexStringToByteArray("020000480001000000000048fefdb4a343cc0784a0416cb2c06b3ee40b04915a249fdb24c9a0a57d4186421f85c220aa32484389ab28faf8d56525107684fb3ce93a59e4a9debace3422e1d4614123002f000000");

    ServerHelloHandler handler;

    TlsContext tlsContext;

    public ServerHelloHandlerTest() {
        tlsContext = new TlsContext();
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.getConfig().setHighestProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setHighestClientProtocolVersion(ProtocolVersion.TLS12);
        tlsContext.setClientSupportedCiphersuites(CipherSuite.getImplemented());
        List<CompressionMethod> implementedCompressions = new LinkedList<>();
        implementedCompressions.add(CompressionMethod.NULL);
        tlsContext.setClientSupportedCompressions(implementedCompressions);
        handler = new ServerHelloHandler(tlsContext);
    }

    /**
     * Test of parseMessageAction method, of class ServerHelloHandler.
     */
    @Test
    public void testParseMessage() {
        handler.initializeProtocolMessage();

        int endPointer = handler.parseMessage(serverHelloWithoutExtensionBytes, 0);
        ServerHelloMessage message = handler.getProtocolMessage();

        assertEquals("Message type must be ServerHello", HandshakeMessageType.SERVER_HELLO,
                message.getHandshakeMessageType());
        assertEquals("Message length must be 70", new Integer(70), message.getLength().getValue());
        assertEquals("Session ID length must be 0x20", new Integer(32), message.getSessionIdLength().getValue());
        assertEquals("Protocol version must be TLS 1.2", ProtocolVersion.TLS12, tlsContext.getSelectedProtocolVersion());
        Assert.assertArrayEquals("Protocol version must be TLS 1.2", ProtocolVersion.TLS12.getValue(), message
                .getProtocolVersion().getValue());

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
                serverHelloWithoutExtensionBytes.length, endPointer);
    }

    @Test
    public void testParseDTLSMessage() {
        tlsContext.setHighestClientProtocolVersion(ProtocolVersion.DTLS12);
        tlsContext.getConfig().setHighestProtocolVersion(ProtocolVersion.DTLS12);
        handler.initializeProtocolMessage();

        int endPointer = handler.parseMessage(serverHelloDTLSnoExtensions, 0);
        ServerHelloMessage message = handler.getProtocolMessage();

        assertEquals("Message type must be ServerHello", HandshakeMessageType.SERVER_HELLO,
                message.getHandshakeMessageType());
        assertEquals("Message length must be 72", new Integer(72), message.getLength().getValue());
        assertEquals("Session ID length must be 0x20", new Integer(32), message.getSessionIdLength().getValue());
        Assert.assertArrayEquals("Protocol version must be DTLS 1.2", ProtocolVersion.DTLS12.getValue(), message
                .getProtocolVersion().getValue());
        assertArrayEquals(
                "Server Session ID",
                ArrayConverter.hexStringToByteArray("aa32484389ab28faf8d56525107684fb3ce93a59e4a9debace3422e1d4614123"),
                message.getSessionId().getValue());
        assertArrayEquals(
                "Server Random",
                ArrayConverter.hexStringToByteArray("b4a343cc0784a0416cb2c06b3ee40b04915a249fdb24c9a0a57d4186421f85c2"),
                tlsContext.getServerRandom());
        Assert.assertArrayEquals("Ciphersuite must be TLS_RSA_WITH_AES_128_CBC_SHA",
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getByteValue(), message.getSelectedCipherSuite()
                        .getOriginalValue());
        assertEquals("Compression must be null", CompressionMethod.NULL,
                CompressionMethod.getCompressionMethod(message.getSelectedCompressionMethod().getOriginalValue()));
    }

    /**
     * Test of parseMessageAction method, of class ServerHelloHandler.
     */
    @Test
    public void testParseMessageWithExtensions() {
        handler.initializeProtocolMessage();

        int endPointer = handler.parseMessage(serverHelloWithHeartbeatBytes, 0);
        ServerHelloMessage message = handler.getProtocolMessage();

        assertEquals("Message type must be ServerHello", HandshakeMessageType.SERVER_HELLO,
                message.getHandshakeMessageType());
        assertEquals("Message length must be 77", new Integer(77), message.getLength().getValue());
        assertEquals("Session ID length must be 0x20", new Integer(32), message.getSessionIdLength().getValue());
        assertEquals("Protocol version must be TLS 1.2", ProtocolVersion.TLS12, tlsContext.getSelectedProtocolVersion());
        Assert.assertArrayEquals("Protocol version must be TLS 1.2", ProtocolVersion.TLS12.getValue(), message
                .getProtocolVersion().getValue());

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
                serverHelloWithHeartbeatBytes.length, endPointer);
    }

    /**
     * Test of prepareMessageAction method, of class ServerHelloHandler.
     */
    @Test
    public void testPrepareMessage() {
        tlsContext.getConfig().setEnforceSettings(true);
        handler.setProtocolMessage(new ServerHelloMessage(tlsContext.getConfig()));

        ServerHelloMessage message = handler.getProtocolMessage();

        tlsContext.setCompressionMethod(CompressionMethod.NULL);
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);

        byte[] returned = handler.prepareMessageAction();
        byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.SERVER_HELLO.getValue() },
                new byte[] { 0x00, 0x00, 0x46 }, ProtocolVersion.TLS12.getValue(), message.getUnixTime().getValue(),
                message.getRandom().getValue(), new byte[] { 0x20 }, message.getSessionId().getValue(),
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getByteValue(),
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
        tlsContext.getConfig().setAddHeartbeatExtension(true);
        tlsContext.getConfig().setAddEllipticCurveExtension(true);
        tlsContext.getConfig().setHeartbeatMode(HeartbeatMode.PEER_ALLOWED_TO_SEND);
        List<NamedCurve> curve = new ArrayList<>();
        curve.add(NamedCurve.SECP160K1);
        curve.add(NamedCurve.SECT163K1);
        tlsContext.getConfig().setNamedCurves(curve);
        handler.setProtocolMessage(new ServerHelloMessage(tlsContext.getConfig()));
        ServerHelloMessage message = handler.getProtocolMessage();
        byte[] returned = handler.prepareMessageAction();
        byte[] expected = ArrayConverter.concatenate(new byte[] { HandshakeMessageType.SERVER_HELLO.getValue() },
                new byte[] { 0x00, 0x00, 0x57 }, ProtocolVersion.TLS12.getValue(), message.getUnixTime().getValue(),
                message.getRandom().getValue(), new byte[] { 0x20 }, message.getSessionId().getValue(),
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getByteValue(),
                new byte[] { CompressionMethod.NULL.getValue() }, new byte[] { 0x00, 0x0F },
                ExtensionType.HEARTBEAT.getValue(),
                new byte[] { 0x00, 0x01, HeartbeatMode.PEER_ALLOWED_TO_SEND.getValue() },
                ExtensionType.ELLIPTIC_CURVES.getValue(), new byte[] { 0x00, 0x06 }, new byte[] { 0x00, 0x04 },
                NamedCurve.SECP160K1.getValue(), NamedCurve.SECT163K1.getValue());

        assertNotNull("Confirm function didn't return 'NULL'", returned);
        System.out.println("Expected: " + ArrayConverter.bytesToHexString(expected));
        System.out.println("Returned: " + ArrayConverter.bytesToHexString(returned));
        assertArrayEquals("Confirm returned message equals the expected message", expected, returned);
    }
}
