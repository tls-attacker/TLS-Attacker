/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.protocol.exception.CryptoException;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.LayerStack;
import de.rub.nds.tlsattacker.core.layer.SpecificSendLayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.hints.QuicFrameLayerHint;
import de.rub.nds.tlsattacker.core.quic.frame.CryptoFrame;
import de.rub.nds.tlsattacker.core.quic.frame.HandshakeDoneFrame;
import de.rub.nds.tlsattacker.core.quic.frame.PaddingFrame;
import de.rub.nds.tlsattacker.core.quic.frame.PingFrame;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacketCryptoComputations;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeUdpTransportHandler;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

public class QuicFrameLayerTest extends AbstractLayerTest {

    private QuicContext quicContext;
    private final byte[] handshakeDoneFrame = DataConverter.hexStringToByteArray("1E");
    private final byte[] pingFrame = DataConverter.hexStringToByteArray("01");
    private final byte[] paddingFrame = DataConverter.hexStringToByteArray("0000000000");
    private final byte[] cryptoFrame = DataConverter.hexStringToByteArray("060005AABBCCDDEE");

    private final byte[] sourceConnectionId =
            DataConverter.hexStringToByteArray("1d541e5371a5e1c6c481b6d7b07f0961");
    private final byte[] destinationConnectionId =
            DataConverter.hexStringToByteArray("8bf5abc395aa5e36e8c0b304a1352aa5");

    @Override
    public void setUpLayerSpecific() {
        QuicDelegate delegate = new QuicDelegate(true);
        delegate.applyDelegate(config);
        FakeUdpTransportHandler udpTransportHandler = new FakeUdpTransportHandler(null);
        tlsContext.setTransportHandler(udpTransportHandler);
        transportHandler = udpTransportHandler;
        quicContext = context.getQuicContext();
        quicContext.setSourceConnectionId(sourceConnectionId);
        quicContext.setFirstDestinationConnectionId(destinationConnectionId);
        quicContext.setDestinationConnectionId(destinationConnectionId);
        context.setLayerStack(
                new LayerStack(context, new QuicFrameLayer(context), new UdpLayer(context)));
        try {
            QuicPacketCryptoComputations.calculateInitialSecrets(quicContext);
        } catch (NoSuchAlgorithmException | CryptoException e) {
            throw new RuntimeException(e);
        }
    }

    private ArrayList<byte[]> getQuicFramesBytes() {
        ArrayList<byte[]> frames = new ArrayList<>();
        frames.add(handshakeDoneFrame);
        frames.add(pingFrame);
        frames.add(paddingFrame);
        frames.add(cryptoFrame);
        return frames;
    }

    private ArrayList<QuicFrame> getQuicFrames() {
        ArrayList<QuicFrame> frames = new ArrayList<>();
        frames.add(new HandshakeDoneFrame());
        frames.add(new PingFrame());
        frames.add(new PaddingFrame(5));
        frames.add(new CryptoFrame(DataConverter.hexStringToByteArray("AABBCCDDEE"), 0, 5));
        return frames;
    }

    @Test
    public void testSendConfiguration() throws IOException {
        ArrayList<QuicFrame> quicFrames = getQuicFrames();
        ArrayList<byte[]> quicFramesBytes = getQuicFramesBytes();
        for (int i = 0; i < quicFrames.size(); i++) {
            tlsContext
                    .getLayerStack()
                    .getLayer(QuicFrameLayer.class)
                    .setLayerConfiguration(
                            new SpecificSendLayerConfiguration<>(
                                    ImplementedLayers.QUICFRAME, quicFrames.get(i)));
            tlsContext.getLayerStack().getLayer(QuicFrameLayer.class).sendConfiguration();

            List<QuicFrame> usedQuicFrames =
                    tlsContext
                            .getLayerStack()
                            .getLayer(QuicFrameLayer.class)
                            .getLayerResult()
                            .getUsedContainers();
            assertEquals(quicFrames.get(i), usedQuicFrames.get(i));
            assertEquals(
                    Arrays.toString(quicFramesBytes.get(i)),
                    Arrays.toString(transportHandler.getSentBytes()));
            transportHandler.resetOutputStream();
        }
    }

    @Test
    public void testSendData() throws IOException {
        // CRYPTO Frame
        byte[] quicFramePayload = DataConverter.hexStringToByteArray("AABBCCDDEE");
        byte[] quicFrameBytes = DataConverter.hexStringToByteArray("060005AABBCCDDEE");
        tlsContext
                .getLayerStack()
                .getLayer(QuicFrameLayer.class)
                .setLayerConfiguration(
                        new SpecificSendLayerConfiguration<>(
                                ImplementedLayers.QUICFRAME, new ArrayList<>()));
        tlsContext
                .getLayerStack()
                .getLayer(QuicFrameLayer.class)
                .sendData(new QuicFrameLayerHint(ProtocolMessageType.HANDSHAKE), quicFramePayload);
        assertEquals(
                Arrays.toString(quicFrameBytes), Arrays.toString(transportHandler.getSentBytes()));

        // Reset
        transportHandler.resetOutputStream();

        // STREAM Frame
        quicFramePayload = DataConverter.hexStringToByteArray("AABBCCDDEE");
        quicFrameBytes =
                DataConverter.hexStringToByteArray(
                        "0E020005AABBCCDDEE000000000000000000000000000000000000000000000000000000");
        tlsContext
                .getLayerStack()
                .getLayer(QuicFrameLayer.class)
                .setLayerConfiguration(
                        new SpecificSendLayerConfiguration<>(
                                ImplementedLayers.QUICFRAME, new ArrayList<>()));
        tlsContext
                .getLayerStack()
                .getLayer(QuicFrameLayer.class)
                .sendData(
                        new QuicFrameLayerHint(ProtocolMessageType.APPLICATION_DATA),
                        quicFramePayload);
        assertEquals(
                Arrays.toString(quicFrameBytes), Arrays.toString(transportHandler.getSentBytes()));
    }

    /**
     * Simulates a QUIC server sending multiple Handshake-level TLS messages (e.g.,
     * EncryptedExtensions, Certificate, CertificateVerify, Finished) as separate CRYPTO frames.
     * Each message must start at the stream offset where the previous one ended, forming a
     * continuous byte stream.
     */
    @Test
    public void testHandshakeCryptoFrameOffsetsAdvance() throws IOException {
        QuicFrameLayer frameLayer = tlsContext.getLayerStack().getLayer(QuicFrameLayer.class);

        byte[] msg1 = new byte[123];
        byte[] msg2 = new byte[794];
        byte[] msg3 = new byte[264];
        Arrays.fill(msg1, (byte) 0xAA);
        Arrays.fill(msg2, (byte) 0xBB);
        Arrays.fill(msg3, (byte) 0xCC);

        // hintedFirstMessage=false: Handshake phase
        QuicFrameLayerHint handshakeHint =
                new QuicFrameLayerHint(ProtocolMessageType.HANDSHAKE, false);

        // Send message 1
        frameLayer.setLayerConfiguration(
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.QUICFRAME, new ArrayList<>()));
        frameLayer.sendData(handshakeHint, msg1);
        List<QuicFrame> produced1 = frameLayer.getLayerResult().getUsedContainers();
        CryptoFrame frame1 = (CryptoFrame) produced1.getLast();
        assertEquals(0L, frame1.getOffsetConfig(), "First handshake message offset must be 0");

        frameLayer.clear();
        transportHandler.resetOutputStream();

        // Send message 2
        frameLayer.setLayerConfiguration(
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.QUICFRAME, new ArrayList<>()));
        frameLayer.sendData(handshakeHint, msg2);
        List<QuicFrame> produced2 = frameLayer.getLayerResult().getUsedContainers();
        CryptoFrame frame2 = (CryptoFrame) produced2.getFirst();
        assertEquals(
                msg1.length,
                frame2.getOffsetConfig(),
                "Second handshake message offset must equal first message length");

        frameLayer.clear();
        transportHandler.resetOutputStream();

        // Send message 3
        frameLayer.setLayerConfiguration(
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.QUICFRAME, new ArrayList<>()));
        frameLayer.sendData(handshakeHint, msg3);
        List<QuicFrame> produced3 = frameLayer.getLayerResult().getUsedContainers();
        CryptoFrame frame3 = (CryptoFrame) produced3.getFirst();
        assertEquals(
                msg1.length + msg2.length,
                frame3.getOffsetConfig(),
                "Third handshake message offset must equal sum of prior message lengths");
    }

    /**
     * Verifies that Initial-phase and Handshake-phase CRYPTO stream offsets are tracked
     * independently. Sending Initial data should not affect Handshake offsets and vice versa.
     */
    @Test
    public void testInitialAndHandshakeOffsetsAreIndependent() throws IOException {
        QuicFrameLayer frameLayer = tlsContext.getLayerStack().getLayer(QuicFrameLayer.class);

        byte[] initialData = new byte[200];
        byte[] handshakeData1 = new byte[150];
        byte[] handshakeData2 = new byte[300];

        QuicFrameLayerHint initialHint =
                new QuicFrameLayerHint(ProtocolMessageType.HANDSHAKE, true);
        QuicFrameLayerHint handshakeHint =
                new QuicFrameLayerHint(ProtocolMessageType.HANDSHAKE, false);

        // Send Initial-phase message
        frameLayer.setLayerConfiguration(
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.QUICFRAME, new ArrayList<>()));
        frameLayer.sendData(initialHint, initialData);
        CryptoFrame initialFrame =
                (CryptoFrame) frameLayer.getLayerResult().getUsedContainers().getFirst();
        assertEquals(0L, initialFrame.getOffsetConfig(), "Initial phase offset starts at 0");

        frameLayer.clear();
        transportHandler.resetOutputStream();

        // Send first Handshake-phase message: offset must be 0
        frameLayer.setLayerConfiguration(
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.QUICFRAME, new ArrayList<>()));
        frameLayer.sendData(handshakeHint, handshakeData1);
        CryptoFrame hsFrame1 =
                (CryptoFrame) frameLayer.getLayerResult().getUsedContainers().getFirst();
        assertEquals(
                0L,
                hsFrame1.getOffsetConfig(),
                "First Handshake message offset must be 0 (independent of Initial phase)");

        frameLayer.clear();
        transportHandler.resetOutputStream();

        // Send second Handshake-phase message: offset must advance by handshakeData1.length
        frameLayer.setLayerConfiguration(
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.QUICFRAME, new ArrayList<>()));
        frameLayer.sendData(handshakeHint, handshakeData2);
        CryptoFrame hsFrame2 =
                (CryptoFrame) frameLayer.getLayerResult().getUsedContainers().getFirst();
        assertEquals(
                handshakeData1.length,
                hsFrame2.getOffsetConfig(),
                "Second Handshake message offset must equal first Handshake message length");
    }

    /** Verifies that clearCryptoFrameBuffer() resets send offsets */
    @Test
    public void testClearCryptoFrameBufferResetsSendOffsets() throws IOException {
        QuicFrameLayer frameLayer = tlsContext.getLayerStack().getLayer(QuicFrameLayer.class);

        byte[] data = new byte[100];
        QuicFrameLayerHint handshakeHint =
                new QuicFrameLayerHint(ProtocolMessageType.HANDSHAKE, false);

        // Send once to advance the offset
        frameLayer.setLayerConfiguration(
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.QUICFRAME, new ArrayList<>()));
        frameLayer.sendData(handshakeHint, data);
        frameLayer.clear();
        transportHandler.resetOutputStream();

        // Clear the crypto frame buffer
        frameLayer.clearCryptoFrameBuffer();

        // Send again: offset should be back to 0
        frameLayer.setLayerConfiguration(
                new SpecificSendLayerConfiguration<>(
                        ImplementedLayers.QUICFRAME, new ArrayList<>()));
        frameLayer.sendData(handshakeHint, data);
        CryptoFrame frame =
                (CryptoFrame) frameLayer.getLayerResult().getUsedContainers().getFirst();
        assertEquals(
                0L,
                frame.getOffsetConfig(),
                "After clearCryptoFrameBuffer, offset must be 0 again");
    }

    @Test
    public void testReceiveData() throws IOException {}

    @Test
    public void testReceiveMoreDataForHint() {}
}
