/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.protocol.exception.EndOfStreamException;
import de.rub.nds.protocol.exception.TimeoutException;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
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
import de.rub.nds.tlsattacker.core.quic.frame.*;
import de.rub.nds.tlsattacker.core.quic.util.VariableLengthIntegerEncoding;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.net.PortUnreachableException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The QuicFrameLayer handles QUIC frames. The encapsulation into QUIC packets happens in the {@link
 * QuicPacketLayer}.
 */
public class QuicFrameLayer
        extends AcknowledgingProtocolLayer<Context, QuicFrameLayerHint, QuicFrame> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Context context;
    private final QuicContext quicContext;

    private final int MAX_FRAME_SIZE;
    private static final int DEFAULT_STREAM_ID = 2;
    private static final int MIN_FRAME_SIZE = 32;

    private long initialPhaseExpectedCryptoFrameOffset = 0;
    private long handshakePhaseExpectedCryptoFrameOffset = 0;
    private long applicationPhaseExpectedCryptoFrameOffset = 0;

    private List<CryptoFrame> cryptoFrameBuffer = new ArrayList<>();

    private boolean hasExperiencedTimeout = false;

    public QuicFrameLayer(Context context) {
        super(ImplementedLayers.QUICFRAME);
        this.context = context;
        this.quicContext = context.getQuicContext();
        this.MAX_FRAME_SIZE = context.getConfig().getQuicMaximumFrameSize();
    }

    /**
     * Sends the given frames of this layer using the lower layer.
     *
     * @return LayerProcessingResult A result object storing information about sending the data
     * @throws IOException When the data cannot be sent
     */
    @Override
    protected LayerProcessingResult<QuicFrame> sendConfigurationInternal() throws IOException {
        LayerConfiguration<QuicFrame> configuration = getLayerConfiguration();

        SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
        QuicPacketLayerHint prevHint = null;

        if (configuration != null
                && configuration.getContainerList() != null
                && !configuration.getContainerList().isEmpty()) {
            for (QuicFrame frame : configuration.getContainerList()) {
                byte[] bytes = writeFrame(frame);
                QuicPacketLayerHint hint = getHintForFrame();
                if (hint != null) {
                    hint = hint.asNewPacket(false);
                }
                addProducedContainer(frame);

                if (prevHint != null
                        && hint != null
                        && !hint.isNewPacket()
                        && prevHint.getQuicPacketType() == hint.getQuicPacketType()
                        && stream.size() != 0) {
                    // Flush packets before the current packet
                    getLowerLayer().sendData(hint, stream.toByteArray());
                    stream.reset();
                }
                stream.writeBytes(bytes);
                prevHint = hint;
            }
            getLowerLayer().sendData(prevHint, stream.toByteArray());
        }
        return getLayerResult();
    }

    /**
     * Sends data from an upper layer using the lower layer. Puts the given bytes into frames and
     * sends those.
     *
     * @param hint Hint for the layer
     * @param data The data to send
     * @return LayerProcessingResult A result object containing information about the sent packets
     * @throws IOException When the data cannot be sent
     */
    @Override
    protected LayerProcessingResult<QuicFrame> sendDataInternal(
            LayerProcessingHint hint, byte[] data) throws IOException {
        ProtocolMessageType hintedType;
        boolean hintedFirstMessage;
        if (hint instanceof QuicFrameLayerHint) {
            hintedType = ((QuicFrameLayerHint) hint).getMessageType();
            hintedFirstMessage = ((QuicFrameLayerHint) hint).isFirstMessage();
        } else {
            hintedType = ProtocolMessageType.UNKNOWN;
            hintedFirstMessage = true;
        }
        if (hint != null && hintedType != null) {
            QuicPacketLayerHint packetLayerHint;
            switch (hintedType) {
                case HANDSHAKE:
                    if (hintedFirstMessage) {
                        packetLayerHint = new QuicPacketLayerHint(QuicPacketType.INITIAL_PACKET);
                    } else {
                        packetLayerHint = new QuicPacketLayerHint(QuicPacketType.HANDSHAKE_PACKET);
                    }
                    List<QuicFrame> givenFrames = getUnprocessedConfiguredContainers();
                    int offset = 0;

                    // Send crypto frames from the configuration (if present)
                    List<CryptoFrame> givenCryptoFrames =
                            givenFrames.stream()
                                    .filter(frame -> frame instanceof CryptoFrame)
                                    .map(frame -> (CryptoFrame) frame)
                                    .toList();
                    for (CryptoFrame frame : givenCryptoFrames) {
                        int toCopy =
                                frame.getMaxFrameLengthConfig() != 0
                                        ? frame.getMaxFrameLengthConfig()
                                        : MAX_FRAME_SIZE;
                        byte[] payload = Arrays.copyOfRange(data, offset, offset + toCopy);
                        frame.setCryptoDataConfig(payload);
                        frame.setOffsetConfig(offset);
                        frame.setLengthConfig(payload.length);
                        addProducedContainer(frame);
                        // TODO: Add option to pass everything together to the next layer
                        getLowerLayer().sendData(packetLayerHint, writeFrame(frame));

                        offset += toCopy;
                        if (offset >= data.length) {
                            break;
                        }
                    }

                    // Send fresh crypto frames if not enough frames were specified explicitly
                    for (; offset < data.length; offset += MAX_FRAME_SIZE) {
                        byte[] payload =
                                Arrays.copyOfRange(
                                        data,
                                        offset,
                                        Math.min(offset + MAX_FRAME_SIZE, data.length));
                        CryptoFrame frame = new CryptoFrame(payload, offset, payload.length);
                        addProducedContainer(frame);
                        // TODO: Add option to pass everything together to the next layer
                        getLowerLayer().sendData(packetLayerHint, writeFrame(frame));
                    }
                    break;
                case APPLICATION_DATA:
                    // TODO: Use existing STREAM frames from the configuration first
                    // prepare hint
                    if (quicContext.isApplicationSecretsInitialized()) {
                        packetLayerHint = new QuicPacketLayerHint(QuicPacketType.ONE_RTT_PACKET);
                    } else {
                        packetLayerHint = new QuicPacketLayerHint(QuicPacketType.ZERO_RTT_PACKET);
                    }
                    // prepare bytes
                    StreamFrame frame = new StreamFrame(data, DEFAULT_STREAM_ID);
                    SilentByteArrayOutputStream stream = new SilentByteArrayOutputStream();
                    stream.writeBytes(writeFrame(frame));
                    addProducedContainer(frame);
                    if (data.length < MIN_FRAME_SIZE) {
                        PaddingFrame paddingFrame = new PaddingFrame(MIN_FRAME_SIZE - data.length);
                        stream.writeBytes(writeFrame(paddingFrame));
                        addProducedContainer(paddingFrame);
                    }
                    getLowerLayer().sendData(packetLayerHint, stream.toByteArray());
                    break;
                default:
                    LOGGER.debug("Unsupported message type: {}", hintedType);
                    break;
            }
        } else {
            throw new UnsupportedOperationException(
                    "No QuicFrameLayerHint passed - Not supported yet.");
        }
        return getLayerResult();
    }

    /**
     * Receives data from the lower layer.
     *
     * @return LayerProcessingResult A result object containing information about the received data.
     */
    @Override
    protected LayerProcessingResult<QuicFrame> receiveDataInternal() {
        try {
            InputStream dataStream;
            do {
                dataStream = getLowerLayer().getDataStream();
                readFrames(dataStream);
            } while (shouldContinueProcessing());
        } catch (SocketTimeoutException | TimeoutException ex) {
            LOGGER.debug("Received a timeout");
            LOGGER.trace(ex);
            hasExperiencedTimeout = true;
        } catch (PortUnreachableException ex) {
            LOGGER.debug("Desitination port unreachable");
            LOGGER.trace(ex);
            hasExperiencedTimeout = true;
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages");
            LOGGER.trace(ex);
            hasExperiencedTimeout = true;
        } catch (IOException ex) {
            LOGGER.warn("The lower layer did not produce a data stream: ", ex);
        }
        return getLayerResult();
    }

    /**
     * Receive more data for the upper layer using the lower layer.
     *
     * @param hint This hint from the calling layer specifies which data its wants to read.
     * @throws IOException When no data can be read
     */
    @Override
    protected void receiveMoreDataForHintInternal(LayerProcessingHint hint) throws IOException {
        try {
            while (currentInputStream == null || currentInputStream.available() == 0) {
                InputStream dataStream = getLowerLayer().getDataStream();

                // For now, we ignore the hint
                readFrames(dataStream);
            }
        } catch (PortUnreachableException ex) {
            LOGGER.debug("Received a ICMP Port Unreachable");
            LOGGER.trace(ex);
            hasExperiencedTimeout = true;
        } catch (SocketTimeoutException | TimeoutException ex) {
            LOGGER.debug("Received a timeout");
            LOGGER.trace(ex);
            hasExperiencedTimeout = true;
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages");
            LOGGER.trace(ex);
            hasExperiencedTimeout = true;
        }
    }

    /** Reads all frames in one QUIC packet and add to frame buffer. */
    private void readFrames(InputStream dataStream) throws IOException {
        PushbackInputStream inputStream = new PushbackInputStream(dataStream);
        RecordLayerHint recordLayerHint = null;
        boolean isAckEliciting = false;

        if (inputStream.available() == 0) {
            throw new EndOfStreamException();
        }
        while (inputStream.available() > 0) {
            long frameTypeNumber =
                    VariableLengthIntegerEncoding.readVariableLengthInteger(inputStream);
            QuicFrameType frameType = QuicFrameType.getFrameType(frameTypeNumber);
            QuicFrame frame =
                    switch (frameType) {
                        case ACK_FRAME -> new AckFrame(false);
                        case ACK_FRAME_WITH_ECN -> new AckFrame(true);
                        case CONNECTION_CLOSE_QUIC_FRAME -> new ConnectionCloseFrame(true);
                        case CONNECTION_CLOSE_APPLICATION_FRAME -> new ConnectionCloseFrame(false);
                        case CRYPTO_FRAME -> {
                            recordLayerHint = new RecordLayerHint(ProtocolMessageType.HANDSHAKE);
                            CryptoFrame cryptoFrame = new CryptoFrame();
                            cryptoFrameBuffer.add(cryptoFrame);
                            yield cryptoFrame;
                        }
                        case HANDSHAKE_DONE_FRAME -> new HandshakeDoneFrame();
                        case NEW_CONNECTION_ID_FRAME -> new NewConnectionIdFrame();
                        case RETIRE_CONNECTION_ID -> new RetireConnectionIdFrame();
                        case NEW_TOKEN_FRAME -> new NewTokenFrame();
                        case PADDING_FRAME -> new PaddingFrame();
                        case PATH_CHALLENGE_FRAME -> new PathChallengeFrame();
                        case PATH_RESPONSE_FRAME -> new PathResponseFrame();
                        case PING_FRAME -> new PingFrame();
                        case STREAM_FRAME,
                                STREAM_FRAME_OFF_LEN_FIN,
                                STREAM_FRAME_OFF_LEN,
                                STREAM_FRAME_LEN_FIN,
                                STREAM_FRAME_OFF_FIN,
                                STREAM_FRAME_FIN,
                                STREAM_FRAME_LEN,
                                STREAM_FRAME_OFF ->
                                new StreamFrame(frameType);
                        case RESET_STREAM_FRAME -> new ResetStreamFrame();
                        case STOP_SENDING_FRAME -> new StopSendingFrame();
                        case MAX_DATA_FRAME -> new MaxDataFrame();
                        case MAX_STREAM_DATA_FRAME -> new MaxStreamDataFrame();
                        case MAX_STREAMS_UNI_FRAME -> new MaxStreamsFrame(false);
                        case MAX_STREAMS_BIDI_FRAME -> new MaxStreamsFrame(true);
                        case DATA_BLOCKED_FRAME -> new DataBlockedFrame();
                        case STREAM_DATA_BLOCKED_FRAME -> new StreamDataBlockedFrame();
                        case STREAMS_BLOCKED_UNI_FRAME -> new StreamsBlockedFrame(false);
                        case STREAMS_BLOCKED_BIDI_FRAME -> new StreamsBlockedFrame(true);
                        case DATAGRAM_FRAME -> new DatagramFrame(false);
                        case DATAGRAM_FRAME_LEN -> new DatagramFrame(true);
                        default -> null;
                    };
            if (frame != null) {
                isAckEliciting |= frame.isAckEliciting();
                frame.setFrameType(frameTypeNumber);
                readDataContainer(frame, context, inputStream);
            } else {
                LOGGER.error("Undefined QUIC frame type: {}", frameTypeNumber);
            }
        }

        // reorder cryptoFrames according to offset and check if they are consecutive and can be
        // passed to the upper layer without gaps
        SilentByteArrayOutputStream outputStream = new SilentByteArrayOutputStream();
        if (!cryptoFrameBuffer.isEmpty()) {
            cryptoFrameBuffer.sort(Comparator.comparingLong(frame -> frame.getOffset().getValue()));
            cryptoFrameBuffer = cryptoFrameBuffer.stream().distinct().collect(Collectors.toList());
            if (isCryptoBufferConsecutive()) {
                for (CryptoFrame frame : cryptoFrameBuffer) {
                    outputStream.write(frame.getCryptoData().getValue());
                }
                CryptoFrame lastFrame = cryptoFrameBuffer.getLast();
                long nextExpectedCryptoOffset =
                        lastFrame.getOffset().getValue() + lastFrame.getLength().getValue();
                if (!quicContext.isHandshakeSecretsInitialized()) {
                    initialPhaseExpectedCryptoFrameOffset = nextExpectedCryptoOffset;
                } else if (!quicContext.isApplicationSecretsInitialized()) {
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
            if (!quicContext.getReceivedPackets().isEmpty()) {
                quicContext.getReceivedPackets().removeLast();
            }
        }

        if (currentInputStream == null) {
            currentInputStream = new HintedLayerInputStream(recordLayerHint, this);
        } else {
            currentInputStream.setHint(recordLayerHint);
        }
        currentInputStream.extendStream(outputStream.toByteArray());

        outputStream.flush();
    }

    private boolean isCryptoBufferConsecutive() {
        long lastSeenCryptoOffset;
        if (!quicContext.isHandshakeSecretsInitialized()) {
            lastSeenCryptoOffset = initialPhaseExpectedCryptoFrameOffset;
        } else if (!quicContext.isApplicationSecretsInitialized()) {
            lastSeenCryptoOffset = handshakePhaseExpectedCryptoFrameOffset;
        } else {
            lastSeenCryptoOffset = applicationPhaseExpectedCryptoFrameOffset;
        }
        if (cryptoFrameBuffer.getFirst().getOffset().getValue() != lastSeenCryptoOffset) {
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

    private byte[] writeFrame(QuicFrame frame) {
        frame.getPreparator(context).prepare();
        return frame.getSerializer(context).serialize();
    }

    private QuicPacketLayerHint getHintForFrame() {
        if (quicContext.isInitialSecretsInitialized()
                && !quicContext.isHandshakeSecretsInitialized()) {
            return new QuicPacketLayerHint(QuicPacketType.INITIAL_PACKET);
        } else if (quicContext.isHandshakeSecretsInitialized()
                && !quicContext.isApplicationSecretsInitialized()) {
            return new QuicPacketLayerHint(QuicPacketType.HANDSHAKE_PACKET);
        } else if (quicContext.isApplicationSecretsInitialized()) {
            return new QuicPacketLayerHint(QuicPacketType.ONE_RTT_PACKET);
        }
        return null;
    }

    @Override
    public void sendAck(byte[] data) {
        AckFrame frame = new AckFrame(false);
        if (quicContext.getReceivedPackets().getLast() == QuicPacketType.INITIAL_PACKET) {
            frame.setLargestAcknowledgedConfig(
                    quicContext.getReceivedInitialPacketNumbers().getLast());
            LOGGER.debug("Send Ack for Initial Packet #{}", frame.getLargestAcknowledgedConfig());
        } else if (quicContext.getReceivedPackets().getLast() == QuicPacketType.HANDSHAKE_PACKET) {
            frame.setLargestAcknowledgedConfig(
                    quicContext.getReceivedHandshakePacketNumbers().getLast());
            LOGGER.debug("Send Ack for Handshake Packet #{}", frame.getLargestAcknowledgedConfig());
        } else if (quicContext.getReceivedPackets().getLast() == QuicPacketType.ONE_RTT_PACKET) {
            frame.setLargestAcknowledgedConfig(
                    quicContext.getReceivedOneRTTPacketNumbers().getLast());
            LOGGER.debug("Send Ack for 1RTT Packet #{}", frame.getLargestAcknowledgedConfig());
        }

        frame.setAckDelayConfig(1);
        frame.setAckRangeCountConfig(0);
        frame.setFirstACKRangeConfig(0);
        ((AcknowledgingProtocolLayer) getLowerLayer()).sendAck(writeFrame(frame));
    }

    /**
     * Clears the frame buffer and reset the variables. This function is typically used when
     * resetting the connection.
     */
    public void clearCryptoFrameBuffer() {
        cryptoFrameBuffer.clear();
        initialPhaseExpectedCryptoFrameOffset = 0;
        handshakePhaseExpectedCryptoFrameOffset = 0;
        applicationPhaseExpectedCryptoFrameOffset = 0;
    }

    public boolean hasExperiencedTimeout() {
        return hasExperiencedTimeout;
    }
}
