/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.Tls13KeySetType;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import org.junit.jupiter.api.Test;

public class FinishedHandlerTest
        extends AbstractProtocolMessageHandlerTest<FinishedMessage, FinishedHandler> {

    public FinishedHandlerTest() {
        super(FinishedMessage::new, FinishedHandler::new);
    }

    /** Test of adjustContext method, of class FinishedHandler. */
    @Test
    @Override
    public void testadjustContext() {
        FinishedMessage message = new FinishedMessage();
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContext(message);

        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, context.getLastClientVerifyData());
        assertArrayEquals(null, context.getLastServerVerifyData());
        assertEquals(Tls13KeySetType.NONE, context.getActiveServerKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveClientKeySetType());

        assertArrayEquals(null, context.getClientApplicationTrafficSecret());
        assertArrayEquals(null, context.getServerApplicationTrafficSecret());
        assertArrayEquals(null, context.getMasterSecret());
    }

    @Test
    public void testadjustContextAfterSerializedTls12() {
        FinishedMessage message = new FinishedMessage();
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertArrayEquals(null, context.getLastClientVerifyData());
        assertArrayEquals(null, context.getLastServerVerifyData());
        assertEquals(Tls13KeySetType.NONE, context.getActiveServerKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveClientKeySetType());

        assertArrayEquals(null, context.getClientApplicationTrafficSecret());
        assertArrayEquals(null, context.getServerApplicationTrafficSecret());
        assertArrayEquals(null, context.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ServerOutbound() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setConnection(new OutboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContext(message);

        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, context.getLastServerVerifyData());
        assertArrayEquals(null, context.getLastClientVerifyData());
        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS, context.getActiveServerKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveClientKeySetType());

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "F8FAD34AEB9E4A8A3233A5F3C01D9E7B25CFAA4CBD7E255426A39B5EA8AE9840"),
                context.getClientApplicationTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "2FC28A45C71076589231CE9095D933E120AFD9F38895CFE2EC8A56B89FBCEF33"),
                context.getServerApplicationTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "9AD9F506B33C740C483E54321EBE59268F7D588356F07ADED4149164D0A18FCA"),
                context.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ServerInbound() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setConnection(new InboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContext(message);

        assertEquals(
                Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS, context.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, context.getLastServerVerifyData());
        assertArrayEquals(null, context.getLastClientVerifyData());

        assertArrayEquals(null, context.getClientApplicationTrafficSecret());
        assertArrayEquals(null, context.getServerApplicationTrafficSecret());
        assertArrayEquals(null, context.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ClientOutbound() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        context.setConnection(new OutboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContext(message);

        assertEquals(
                Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS, context.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, context.getLastClientVerifyData());
        assertArrayEquals(null, context.getLastServerVerifyData());

        assertArrayEquals(null, context.getClientApplicationTrafficSecret());
        assertArrayEquals(null, context.getServerApplicationTrafficSecret());
        assertArrayEquals(null, context.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ClientInbound() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        context.setConnection(new InboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContext(message);

        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS, context.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, context.getLastClientVerifyData());
        assertArrayEquals(null, context.getLastServerVerifyData());

        assertArrayEquals(null, context.getClientApplicationTrafficSecret());
        assertArrayEquals(null, context.getServerApplicationTrafficSecret());
        assertArrayEquals(null, context.getMasterSecret());
    }

    @Test
    public void testadjustContextAfterSerializedTls13ClientInbound() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        context.setConnection(new InboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertEquals(Tls13KeySetType.NONE, context.getActiveClientKeySetType());
        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS, context.getActiveServerKeySetType());
        assertArrayEquals(null, context.getLastClientVerifyData());
        assertArrayEquals(null, context.getLastServerVerifyData());

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "F8FAD34AEB9E4A8A3233A5F3C01D9E7B25CFAA4CBD7E255426A39B5EA8AE9840"),
                context.getClientApplicationTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "2FC28A45C71076589231CE9095D933E120AFD9F38895CFE2EC8A56B89FBCEF33"),
                context.getServerApplicationTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "9AD9F506B33C740C483E54321EBE59268F7D588356F07ADED4149164D0A18FCA"),
                context.getMasterSecret());
    }

    @Test
    public void testadjustContextAfterSerializedTls13ClientOutbound() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        context.setConnection(new OutboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS, context.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveServerKeySetType());
        assertArrayEquals(null, context.getLastClientVerifyData());
        assertArrayEquals(null, context.getLastServerVerifyData());
    }

    @Test
    public void testadjustContextAfterSerializeTls13ServerOutbound() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setConnection(new OutboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertArrayEquals(null, context.getLastServerVerifyData());
        assertArrayEquals(null, context.getLastClientVerifyData());
        assertEquals(Tls13KeySetType.NONE, context.getActiveServerKeySetType());
        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS, context.getActiveClientKeySetType());
    }

    @Test
    public void testadjustContextAfterSerializeTls13ServerInbound() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setConnection(new InboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertArrayEquals(null, context.getLastServerVerifyData());
        assertArrayEquals(null, context.getLastClientVerifyData());
        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS, context.getActiveServerKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveClientKeySetType());

        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "F8FAD34AEB9E4A8A3233A5F3C01D9E7B25CFAA4CBD7E255426A39B5EA8AE9840"),
                context.getClientApplicationTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "2FC28A45C71076589231CE9095D933E120AFD9F38895CFE2EC8A56B89FBCEF33"),
                context.getServerApplicationTrafficSecret());
        assertArrayEquals(
                ArrayConverter.hexStringToByteArray(
                        "9AD9F506B33C740C483E54321EBE59268F7D588356F07ADED4149164D0A18FCA"),
                context.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ServerInboundWithoutEarlyData() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setConnection(new InboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});
        context.getNegotiatedExtensionSet().remove(ExtensionType.EARLY_DATA);

        handler.adjustContext(message);

        assertEquals(
                Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS, context.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, context.getLastServerVerifyData());
        assertArrayEquals(null, context.getLastClientVerifyData());

        assertArrayEquals(null, context.getClientApplicationTrafficSecret());
        assertArrayEquals(null, context.getServerApplicationTrafficSecret());
        assertArrayEquals(null, context.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ServerInboundWithEarlyData() {
        FinishedMessage message = new FinishedMessage();
        context.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        context.setConnection(new InboundConnection());
        context.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        context.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        context.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});
        context.getNegotiatedExtensionSet().add(ExtensionType.EARLY_DATA);

        handler.adjustContext(message);

        assertEquals(Tls13KeySetType.NONE, context.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, context.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, context.getLastServerVerifyData());
        assertArrayEquals(null, context.getLastClientVerifyData());

        assertArrayEquals(null, context.getClientApplicationTrafficSecret());
        assertArrayEquals(null, context.getServerApplicationTrafficSecret());
        assertArrayEquals(null, context.getMasterSecret());
    }
}
