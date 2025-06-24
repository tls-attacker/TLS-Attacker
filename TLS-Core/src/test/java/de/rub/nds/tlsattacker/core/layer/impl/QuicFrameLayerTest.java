/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import static junit.framework.Assert.assertEquals;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.tlsattacker.core.config.delegate.QuicDelegate;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
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

    @Test
    public void testReceiveData() throws IOException {}

    @Test
    public void testReceiveMoreDataForHint() {}
}
