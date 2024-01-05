/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.layer.AcknowledgingProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.QuicFrameLayerHint;
import de.rub.nds.tlsattacker.core.layer.hints.QuicPacketLayerHint;
import de.rub.nds.tlsattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.quic.constants.QuicFrameType;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.frame.AckFrame;
import de.rub.nds.tlsattacker.core.quic.frame.ConnectionCloseFrame;
import de.rub.nds.tlsattacker.core.quic.frame.CryptoFrame;
import de.rub.nds.tlsattacker.core.quic.frame.HandshakeDoneFrame;
import de.rub.nds.tlsattacker.core.quic.frame.NewConnectionIdFrame;
import de.rub.nds.tlsattacker.core.quic.frame.NewTokenFrame;
import de.rub.nds.tlsattacker.core.quic.frame.PaddingFrame;
import de.rub.nds.tlsattacker.core.quic.frame.PathChallengeFrame;
import de.rub.nds.tlsattacker.core.quic.frame.PingFrame;
import de.rub.nds.tlsattacker.core.quic.frame.QuicFrame;
import de.rub.nds.tlsattacker.core.quic.frame.StreamFrame;
import de.rub.nds.tlsattacker.core.quic.serializer.frame.QuicFrameSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicFrameLayer extends AcknowledgingProtocolLayer<QuicFrameLayerHint, QuicFrame> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final QuicContext context;

    // chosen so total packet does not exceed 1200 bytes, packet header lengths are not known at
    // this stage
    // so the max frame size can not be calculated for perfect fit (padding added in packet layer
    // for exact packet size of 1200)
    private static final int MAX_FRAME_SIZE = 1100;

    private long initialPhaseExpectedCryptoFrameOffset = 0;
    private long handshakePhaseExpectedCryptoFrameOffset = 0;
    private long applicationPhaseExpectedCryptoFrameOffset = 0;

    private List<CryptoFrame> cryptoFrameBuffer = new ArrayList<>();

    public QuicFrameLayer(QuicContext context) {
        super(ImplementedLayers.QUICFRAME);
        this.context = context;
    }

    public void clearCryptoFrameBuffer() {
        cryptoFrameBuffer.clear();
        initialPhaseExpectedCryptoFrameOffset = 0;
        handshakePhaseExpectedCryptoFrameOffset = 0;
        applicationPhaseExpectedCryptoFrameOffset = 0;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<QuicFrame> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (QuicFrame frame : configuration.getContainerList()) {
                QuicPacketLayerHint packetLayerHint = null;
                switch (QuicFrameType.getFrameType(frame.getFrameType().getValue())) {
                    case CRYPTO_FRAME:
                        stream.writeBytes(writeCryptoFrame(new byte[0], (CryptoFrame) frame));
                        break;
                    case CONNECTION_CLOSE_FRAME:
                    case PING_FRAME:
                    case PATH_RESPONSE_FRAME:
                        stream.writeBytes(writeFrame(frame));
                        if (context.isApplicationSecretsInitialized()) {
                            packetLayerHint =
                                    new QuicPacketLayerHint(QuicPacketType.ONE_RTT_PACKET);
                        } else if (context.isHandshakeSecretsInitialized()) {
                            packetLayerHint =
                                    new QuicPacketLayerHint(QuicPacketType.HANDSHAKE_PACKET);
                        }
                        break;
                    default:
                        break;
                }
                getLowerLayer().sendData(packetLayerHint, stream.toByteArray());
                stream.flush();
            }
            setLayerConfiguration(null);
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(QuicFrameLayerHint hint, byte[] data) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        if (hint != null && hint.getMessageType() != null) {
            QuicPacketLayerHint packetLayerHint;
            if (hint.isFirstMessage()) {
                packetLayerHint = new QuicPacketLayerHint(QuicPacketType.INITIAL_PACKET);
            } else {
                packetLayerHint = new QuicPacketLayerHint(QuicPacketType.HANDSHAKE_PACKET);
            }
            switch (hint.getMessageType()) {
                case HANDSHAKE:
                    // fragment data into multiple crypto frames and send in multiple packets to
                    // adhere to maximum initial packet size
                    for (int offset = 0; offset < data.length; offset += MAX_FRAME_SIZE) {
                        stream.writeBytes(
                                writeCryptoFrame(
                                        Arrays.copyOfRange(
                                                data,
                                                offset,
                                                Math.min(offset + MAX_FRAME_SIZE, data.length)),
                                        new CryptoFrame(),
                                        offset));
                        getLowerLayer().sendData(packetLayerHint, stream.toByteArray());
                        stream = new ByteArrayOutputStream();
                    }
                    break;
                case APPLICATION_DATA:
                    if (context.isApplicationSecretsInitialized()) {
                        packetLayerHint = new QuicPacketLayerHint(QuicPacketType.ONE_RTT_PACKET);
                    } else {
                        packetLayerHint = new QuicPacketLayerHint(QuicPacketType.ZERO_RTT_PACKET);
                    }
                    stream.writeBytes(writeFrame(new StreamFrame(data, 2)));
                    if (data.length < 32) {
                        stream.writeBytes(writeFrame(new PaddingFrame(32 - data.length)));
                    }
                    getLowerLayer().sendData(packetLayerHint, stream.toByteArray());
                    break;
            }
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult receiveData() {
        LOGGER.debug("Receive Data");
        try {
            InputStream dataStream = getLowerLayer().getDataStream();
            readFrames(dataStream);

        } catch (IOException e) {
            // the lower layer does not give us any data so we can simply return here
            LOGGER.warn("The lower layer did not produce a data stream: ", e);
        }
        return getLayerResult();
    }

    @Override
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        LOGGER.debug("Receive Data for Hint {}", hint);
        InputStream dataStream = getLowerLayer().getDataStream();
        readFrames(dataStream);
    }

    private void readFrames(InputStream dataStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PushbackInputStream inputStream = new PushbackInputStream(dataStream);
        RecordLayerHint recordLayerHint = null;
        boolean isAckEliciting = false;

        while (inputStream.available() > 0) {
            int firstByte = inputStream.read();
            QuicFrameType frameType = QuicFrameType.getFrameType((byte) firstByte);

            switch (frameType) {
                case ACK_FRAME:
                    readDataContainer(new AckFrame(), context, dataStream);
                    LOGGER.debug("Read {}", frameType);
                    break;
                case CONNECTION_CLOSE_FRAME:
                    LOGGER.error(
                            "Received Connection Close Frame:\n{}",
                            readConnectionCloseFrame(inputStream));
                    break;
                case CRYPTO_FRAME:
                    isAckEliciting = true;
                    recordLayerHint = new RecordLayerHint(ProtocolMessageType.HANDSHAKE);
                    cryptoFrameBuffer.add(readCryptoFrame(inputStream));
                    LOGGER.debug("Read {}", frameType);
                    break;
                case HANDSHAKE_DONE_FRAME:
                    isAckEliciting = true;
                    readDataContainer(new HandshakeDoneFrame(), context, inputStream);
                    LOGGER.debug("Read {}", frameType);
                    break;
                case NEW_CONNECTION_ID_FRAME:
                    readDataContainer(new NewConnectionIdFrame(), context, inputStream);
                    LOGGER.debug("Read {}", frameType);
                    break;
                case NEW_TOKEN_FRAME:
                    readDataContainer(new NewTokenFrame(), context, inputStream);
                    LOGGER.debug("Read {}", frameType);
                    break;
                case PADDING_FRAME:
                    readDataContainer(new PaddingFrame(), context, inputStream);
                    LOGGER.debug("Read {}", frameType);
                    break;
                case PATH_CHALLENGE_FRAME:
                    readDataContainer(new PathChallengeFrame(), context, inputStream);
                    LOGGER.debug("Read {}", frameType);
                    break;
                case PING_FRAME:
                    readDataContainer(new PingFrame(), context, inputStream);
                    isAckEliciting = true;
                    break;
                case STREAM_FRAME:
                case STREAM_FRAME_OFF_LEN_FIN:
                case STREAM_FRAME_OFF_LEN:
                case STREAM_FRAME_LEN_FIN:
                case STREAM_FRAME_OFF_FIN:
                case STREAM_FRAME_FIN:
                case STREAM_FRAME_LEN:
                case STREAM_FRAME_OFF:
                    isAckEliciting = true;
                    readDataContainer(new StreamFrame(frameType), context, inputStream);
                    break;

                default:
                    LOGGER.warn(
                            "Received unsupport Quic Frame Type {} byte={}. Will be ignored.",
                            frameType,
                            Integer.toHexString(firstByte));
                    recordLayerHint = null;
                    break;
            }
        }

        // reorder cryptoFrames according to offset and check if they are consecutive and can be
        // passed to the upper layer
        // crypto frames can appear in random order across multiple packets, therefore a buffer is
        // required to ensure that
        // the crypto data is passed to the upper layer in the correct order and without gaps
        // rfc9000 section 19.6
        // There is a separate flow of cryptographic handshake data in each encryption level, each
        // of which starts at an offset of 0.
        // This implies that each encryption level is treated as a separate CRYPTO stream of data.
        if (!cryptoFrameBuffer.isEmpty()) {
            cryptoFrameBuffer.sort(Comparator.comparingLong(frame -> frame.getOffset().getValue()));
            cryptoFrameBuffer = cryptoFrameBuffer.stream().distinct().collect(Collectors.toList());
            if (isCryptoBufferConsecutive()) {
                for (CryptoFrame frame : cryptoFrameBuffer) {
                    outputStream.write(frame.getCryptoData().getValue());
                }
                CryptoFrame lastFrame = cryptoFrameBuffer.get(cryptoFrameBuffer.size() - 1);
                long nextExpectedCryptoOffset =
                        lastFrame.getOffset().getValue() + lastFrame.getLength().getValue();
                if (!context.isHandshakeSecretsInitialized()) {
                    initialPhaseExpectedCryptoFrameOffset = nextExpectedCryptoOffset;
                } else if (!context.isApplicationSecretsInitialized()) {
                    handshakePhaseExpectedCryptoFrameOffset = nextExpectedCryptoOffset;
                } else {
                    applicationPhaseExpectedCryptoFrameOffset = nextExpectedCryptoOffset;
                }
                cryptoFrameBuffer.clear();
            }
        }

        if (isAckEliciting) {
            sendAck(null);
        } else {
            if (!context.getReceivedPackets().isEmpty()) {
                context.getReceivedPackets().removeLast();
            }
        }

        if (currentInputStream == null) {
            currentInputStream = new HintedLayerInputStream(recordLayerHint, this);
            currentInputStream.extendStream(outputStream.toByteArray());
        } else {
            currentInputStream.setHint(recordLayerHint);
            currentInputStream.extendStream(outputStream.toByteArray());
        }

        outputStream.flush();
    }

    private boolean isCryptoBufferConsecutive() {
        long lastSeenCryptoOffset;
        if (!context.isHandshakeSecretsInitialized()) {
            lastSeenCryptoOffset = initialPhaseExpectedCryptoFrameOffset;
        } else if (!context.isApplicationSecretsInitialized()) {
            lastSeenCryptoOffset = handshakePhaseExpectedCryptoFrameOffset;
        } else {
            lastSeenCryptoOffset = applicationPhaseExpectedCryptoFrameOffset;
        }
        if (cryptoFrameBuffer.get(0).getOffset().getValue() != lastSeenCryptoOffset) {
            LOGGER.warn(
                    "Missing CryptoFrames in buffer: {}, lastSeenCryptoOffset={}",
                    cryptoBufferToString(),
                    lastSeenCryptoOffset);
            return false;
        }
        for (int i = 1; i < cryptoFrameBuffer.size(); i++) {
            if (cryptoFrameBuffer.get(i).getOffset().getValue()
                    != cryptoFrameBuffer.get(i - 1).getOffset().getValue()
                            + cryptoFrameBuffer.get(i - 1).getLength().getValue()) {
                LOGGER.warn(
                        "Missing CryptoFrames in buffer: {}, lastSeenCryptoOffset={}",
                        cryptoBufferToString(),
                        lastSeenCryptoOffset);
                return false;
            }
        }
        return true;
    }

    private String cryptoBufferToString() {
        return cryptoFrameBuffer.stream()
                .map(
                        cryptoFrame ->
                                "o: "
                                        + cryptoFrame.getOffset().getValue()
                                        + ", l: "
                                        + cryptoFrame.getLength().getValue())
                .collect(Collectors.joining(" | "));
    }

    protected ConnectionCloseFrame readConnectionCloseFrame(InputStream dataStream) {
        ConnectionCloseFrame frame = new ConnectionCloseFrame();
        readDataContainer(frame, context, dataStream);
        return frame;
    }

    protected CryptoFrame readCryptoFrame(InputStream dataStream) {
        CryptoFrame frame = new CryptoFrame();
        readDataContainer(frame, context, dataStream);
        return frame;
    }

    protected byte[] writeFrame(QuicFrame frame) {
        frame.getPreparator(context).prepare();
        QuicFrameSerializer serializer = frame.getSerializer(context);
        addProducedContainer(frame);
        return serializer.serialize();
    }

    protected byte[] writeCryptoFrame(byte[] data, CryptoFrame frame) {
        return writeCryptoFrame(data, frame, 0);
    }

    protected byte[] writeCryptoFrame(byte[] data, CryptoFrame frame, int offset) {
        frame.setLength(data.length);
        frame.setOffset(offset);
        frame.setCryptoData(data);
        return writeFrame(frame);
    }

    @Override
    public void sendAck(byte[] data) {
        AckFrame frame = new AckFrame();
        if (context.getReceivedPackets().getLast() == QuicPacketType.INITIAL_PACKET) {
            frame.setLargestAcknowledged(context.getReceivedInitialPacketNumbers().getLast());
            LOGGER.debug(
                    "Send Ack for Initial Packet #{}", frame.getLargestAcknowledged().getValue());
        } else if (context.getReceivedPackets().getLast() == QuicPacketType.HANDSHAKE_PACKET) {
            frame.setLargestAcknowledged(context.getReceivedHandshakePacketNumbers().getLast());
            LOGGER.debug(
                    "Send Ack for Handshake Packet #{}", frame.getLargestAcknowledged().getValue());
        } else if (context.getReceivedPackets().getLast() == QuicPacketType.ONE_RTT_PACKET) {
            frame.setLargestAcknowledged(context.getReceivedOneRTTPacketNumbers().getLast());
            LOGGER.debug("Send Ack for 1RTT Packet #{}", frame.getLargestAcknowledged().getValue());
        }

        frame.setAckDelay(1);
        frame.setAckRangeCount(0);
        frame.setFirstACKRange(0);
        ((AcknowledgingProtocolLayer) getLowerLayer()).sendAck(writeFrame(frame));
    }
}
