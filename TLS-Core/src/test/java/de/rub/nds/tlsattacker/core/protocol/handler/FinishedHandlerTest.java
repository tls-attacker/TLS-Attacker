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

import de.rub.nds.modifiablevariable.util.DataConverter;
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

        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, tlsContext.getLastClientVerifyData());
        assertArrayEquals(null, tlsContext.getLastServerVerifyData());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveServerKeySetType());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveClientKeySetType());

        assertArrayEquals(null, tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getMasterSecret());
    }

    @Test
    public void testadjustContextAfterSerializedTls12() {
        FinishedMessage message = new FinishedMessage();
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertArrayEquals(null, tlsContext.getLastClientVerifyData());
        assertArrayEquals(null, tlsContext.getLastServerVerifyData());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveServerKeySetType());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveClientKeySetType());

        assertArrayEquals(null, tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ServerOutbound() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        tlsContext.setConnection(new OutboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContext(message);

        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, tlsContext.getLastServerVerifyData());
        assertArrayEquals(null, tlsContext.getLastClientVerifyData());
        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS,
                tlsContext.getActiveServerKeySetType());
        assertEquals(
                Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS, tlsContext.getActiveClientKeySetType());

        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "F8FAD34AEB9E4A8A3233A5F3C01D9E7B25CFAA4CBD7E255426A39B5EA8AE9840"),
                tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "2FC28A45C71076589231CE9095D933E120AFD9F38895CFE2EC8A56B89FBCEF33"),
                tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "9AD9F506B33C740C483E54321EBE59268F7D588356F07ADED4149164D0A18FCA"),
                tlsContext.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ServerInbound() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        tlsContext.setConnection(new InboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContext(message);

        assertEquals(
                Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS, tlsContext.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, tlsContext.getLastServerVerifyData());
        assertArrayEquals(null, tlsContext.getLastClientVerifyData());

        assertArrayEquals(null, tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ClientOutbound() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        tlsContext.setConnection(new OutboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContext(message);

        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, tlsContext.getLastClientVerifyData());
        assertArrayEquals(null, tlsContext.getLastServerVerifyData());

        assertArrayEquals(null, tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ClientInbound() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        tlsContext.setConnection(new InboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContext(message);

        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS,
                tlsContext.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, tlsContext.getLastClientVerifyData());
        assertArrayEquals(null, tlsContext.getLastServerVerifyData());

        assertArrayEquals(null, tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getMasterSecret());
    }

    @Test
    public void testadjustContextAfterSerializedTls13ClientInbound() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        tlsContext.setConnection(new InboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveClientKeySetType());
        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS,
                tlsContext.getActiveServerKeySetType());
        assertArrayEquals(null, tlsContext.getLastClientVerifyData());
        assertArrayEquals(null, tlsContext.getLastServerVerifyData());

        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "F8FAD34AEB9E4A8A3233A5F3C01D9E7B25CFAA4CBD7E255426A39B5EA8AE9840"),
                tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "2FC28A45C71076589231CE9095D933E120AFD9F38895CFE2EC8A56B89FBCEF33"),
                tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "9AD9F506B33C740C483E54321EBE59268F7D588356F07ADED4149164D0A18FCA"),
                tlsContext.getMasterSecret());
    }

    @Test
    public void testadjustContextAfterSerializedTls13ClientOutbound() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        tlsContext.setConnection(new OutboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS,
                tlsContext.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveServerKeySetType());
        assertArrayEquals(null, tlsContext.getLastClientVerifyData());
        assertArrayEquals(null, tlsContext.getLastServerVerifyData());
    }

    @Test
    public void testadjustContextAfterSerializeTls13ServerOutbound() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        tlsContext.setConnection(new OutboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertArrayEquals(null, tlsContext.getLastServerVerifyData());
        assertArrayEquals(null, tlsContext.getLastClientVerifyData());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveServerKeySetType());
        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS,
                tlsContext.getActiveClientKeySetType());
    }

    @Test
    public void testadjustContextAfterSerializeTls13ServerInbound() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        tlsContext.setConnection(new InboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});

        handler.adjustContextAfterSerialize(message);

        assertArrayEquals(null, tlsContext.getLastServerVerifyData());
        assertArrayEquals(null, tlsContext.getLastClientVerifyData());
        assertEquals(
                Tls13KeySetType.APPLICATION_TRAFFIC_SECRETS,
                tlsContext.getActiveServerKeySetType());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveClientKeySetType());

        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "F8FAD34AEB9E4A8A3233A5F3C01D9E7B25CFAA4CBD7E255426A39B5EA8AE9840"),
                tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "2FC28A45C71076589231CE9095D933E120AFD9F38895CFE2EC8A56B89FBCEF33"),
                tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(
                DataConverter.hexStringToByteArray(
                        "9AD9F506B33C740C483E54321EBE59268F7D588356F07ADED4149164D0A18FCA"),
                tlsContext.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ServerInboundWithoutEarlyData() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        tlsContext.setConnection(new InboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});
        tlsContext.getNegotiatedExtensionSet().remove(ExtensionType.EARLY_DATA);

        handler.adjustContext(message);

        assertEquals(
                Tls13KeySetType.HANDSHAKE_TRAFFIC_SECRETS, tlsContext.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, tlsContext.getLastServerVerifyData());
        assertArrayEquals(null, tlsContext.getLastClientVerifyData());

        assertArrayEquals(null, tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getMasterSecret());
    }

    @Test
    public void testadjustContextTls13ServerInboundWithEarlyData() {
        FinishedMessage message = new FinishedMessage();
        tlsContext.setTalkingConnectionEndType(ConnectionEndType.SERVER);
        tlsContext.setConnection(new InboundConnection());
        tlsContext.setSelectedProtocolVersion(ProtocolVersion.TLS13);
        tlsContext.setHandshakeSecret(new byte[] {0, 1, 2, 3, 4});
        tlsContext.setSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        message.setVerifyData(new byte[] {0, 1, 2, 3, 4});
        tlsContext.getNegotiatedExtensionSet().add(ExtensionType.EARLY_DATA);

        handler.adjustContext(message);

        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveClientKeySetType());
        assertEquals(Tls13KeySetType.NONE, tlsContext.getActiveServerKeySetType());
        assertArrayEquals(new byte[] {0, 1, 2, 3, 4}, tlsContext.getLastServerVerifyData());
        assertArrayEquals(null, tlsContext.getLastClientVerifyData());

        assertArrayEquals(null, tlsContext.getClientApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getServerApplicationTrafficSecret());
        assertArrayEquals(null, tlsContext.getMasterSecret());
    }
}
