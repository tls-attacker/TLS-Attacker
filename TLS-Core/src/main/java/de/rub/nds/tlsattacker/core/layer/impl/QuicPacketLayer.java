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
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoRuntimeException;
import de.rub.nds.tlsattacker.core.exceptions.TimeoutException;
import de.rub.nds.tlsattacker.core.layer.AcknowledgingProtocolLayer;
import de.rub.nds.tlsattacker.core.layer.LayerConfiguration;
import de.rub.nds.tlsattacker.core.layer.LayerProcessingResult;
import de.rub.nds.tlsattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.tlsattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.tlsattacker.core.layer.hints.QuicPacketLayerHint;
import de.rub.nds.tlsattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketByteLength;
import de.rub.nds.tlsattacker.core.quic.constants.QuicPacketType;
import de.rub.nds.tlsattacker.core.quic.constants.QuicVersion;
import de.rub.nds.tlsattacker.core.quic.crypto.QuicDecryptor;
import de.rub.nds.tlsattacker.core.quic.crypto.QuicEncryptor;
import de.rub.nds.tlsattacker.core.quic.packet.HandshakePacket;
import de.rub.nds.tlsattacker.core.quic.packet.InitialPacket;
import de.rub.nds.tlsattacker.core.quic.packet.OneRTTPacket;
import de.rub.nds.tlsattacker.core.quic.packet.QuicPacket;
import de.rub.nds.tlsattacker.core.quic.packet.RetryPacket;
import de.rub.nds.tlsattacker.core.quic.packet.VersionNegotiationPacket;
import de.rub.nds.tlsattacker.core.quic.packet.ZeroRTTPacket;
import de.rub.nds.tlsattacker.core.state.Context;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The QuicPacketLayer encrypts and encapsulates QUIC frames into QUIC packets. It sends the packets
 * using the lower layer.
 */
public class QuicPacketLayer extends AcknowledgingProtocolLayer<QuicPacketLayerHint, QuicPacket> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Context context;
    private final QuicContext quicContext;

    private final QuicDecryptor decryptor;
    private final QuicEncryptor encryptor;

    private final Map<QuicPacketType, ArrayList<QuicPacket>> receivedPacketBuffer = new HashMap<>();

    public QuicPacketLayer(Context context) {
        super(ImplementedLayers.QUICPACKET);
        this.context = context;
        this.quicContext = context.getQuicContext();
        decryptor = new QuicDecryptor(context.getQuicContext());
        encryptor = new QuicEncryptor(context.getQuicContext());
        Arrays.stream(QuicPacketType.values())
                .forEach(
                        quicPacketType ->
                                receivedPacketBuffer.put(quicPacketType, new ArrayList<>()));
    }

    /**
     * Sends the given packets of this layer using the lower layer.
     *
     * @return LayerProcessingResult A result object storing information about sending the data
     * @throws IOException When the data cannot be sent
     */
    @Override
    public LayerProcessingResult<QuicPacket> sendConfiguration() throws IOException {
        LayerConfiguration<QuicPacket> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (QuicPacket packet : getUnprocessedConfiguredContainers()) {
                if (isEmptyPacket(packet)) {
                    continue;
                }
                try {
                    byte[] bytes = writePacket(packet);
                    addProducedContainer(packet);
                    getLowerLayer().sendData(null, bytes);
                } catch (CryptoException ex) {
                    LOGGER.error(ex);
                }
            }
        }
        return getLayerResult();
    }

    /**
     * Sends data from an upper layer using the lower layer. Puts the given bytes into packets and
     * sends those.
     *
     * @param hint Hint for the layer
     * @param data The data to send
     * @return LayerProcessingResult A result object containing information about the sent packets
     * @throws IOException When the data cannot be sent
     */
    @Override
    public LayerProcessingResult<QuicPacket> sendData(LayerProcessingHint hint, byte[] data)
            throws IOException {
        QuicPacketType hintedType = QuicPacketType.UNKNOWN;
        if (hint != null && hint instanceof QuicPacketLayerHint) {
            hintedType = ((QuicPacketLayerHint) hint).getQuicPacketType();
        } else {
            LOGGER.warn(
                    "Sending packet without a LayerProcessing hint. Using UNKNOWN as the type.");
        }

        List<QuicPacket> givenPackets = getUnprocessedConfiguredContainers();
        try {
            if (getLayerConfiguration().getContainerList() != null && givenPackets.size() > 0) {
                // If a configuration is provided, the hint will be ignored.
                QuicPacket packet = givenPackets.get(0);
                byte[] bytes = writePacket(data, packet);
                addProducedContainer(packet);
                getLowerLayer().sendData(null, bytes);
            } else {
                switch (hintedType) {
                    case INITIAL_PACKET:
                        InitialPacket initialPacket = new InitialPacket();
                        byte[] initialPacketBytes = writePacket(data, initialPacket);
                        addProducedContainer(initialPacket);
                        getLowerLayer().sendData(null, initialPacketBytes);
                        break;
                    case HANDSHAKE_PACKET:
                        HandshakePacket handshakePacket = new HandshakePacket();
                        byte[] handshakePacketBytes = writePacket(data, handshakePacket);
                        addProducedContainer(handshakePacket);
                        getLowerLayer().sendData(null, handshakePacketBytes);
                        break;
                    case ONE_RTT_PACKET:
                        OneRTTPacket oneRTTPacket = new OneRTTPacket();
                        byte[] oneRTTPacketBytes = writePacket(data, oneRTTPacket);
                        addProducedContainer(oneRTTPacket);
                        getLowerLayer().sendData(null, oneRTTPacketBytes);
                        break;
                    case ZERO_RTT_PACKET:
                        ZeroRTTPacket zeroRTTPacket = new ZeroRTTPacket();
                        byte[] zeroRTTPacketBytes = writePacket(data, zeroRTTPacket);
                        addProducedContainer(zeroRTTPacket);
                        getLowerLayer().sendData(null, zeroRTTPacketBytes);
                        break;
                    case RETRY_PACKET:
                        throw new UnsupportedOperationException(
                                "Retry Packet - Not supported yet.");
                    case VERSION_NEGOTIATION:
                        throw new UnsupportedOperationException(
                                "Version Negotiation Packet - Not supported yet.");
                    case UNKNOWN:
                        throw new UnsupportedOperationException(
                                "Unknown Packet - Not supported yet.");
                    default:
                        break;
                }
            }
        } catch (CryptoException ex) {
            LOGGER.error(ex);
        }
        return getLayerResult();
    }

    /**
     * Receives data from the lower layer.
     *
     * @return LayerProcessingResult A result object containing information about the received data.
     */
    @Override
    public LayerProcessingResult<QuicPacket> receiveData() {
        try {
            InputStream dataStream;
            do {
                try {
                    dataStream = getLowerLayer().getDataStream();
                    readPackets(dataStream);
                } catch (IOException ex) {
                    LOGGER.warn("The lower layer did not produce a data stream: ", ex);
                    return getLayerResult();
                }
            } while (shouldContinueProcessing());
        } catch (TimeoutException ex) {
            LOGGER.debug("Received a timeout");
            LOGGER.trace(ex);
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages");
            LOGGER.trace(ex);
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
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        try {
            InputStream dataStream;
            try {
                dataStream = getLowerLayer().getDataStream();
                // For now, we ignore the hint.
                readPackets(dataStream);
            } catch (IOException ex) {
                LOGGER.warn("The lower layer did not produce a data stream: ", ex);
            }
        } catch (TimeoutException ex) {
            LOGGER.debug("Received a timeout");
            LOGGER.trace(ex);
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages");
            LOGGER.trace(ex);
        }
    }

    /** Reads all packets in one UDP datagram and add to packet buffer. */
    private void readPackets(InputStream dataStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        int firstByte = dataStream.read();
        if (firstByte == 0x00) {
            // If the first byte is 0, it indicates UDP padding. In this case, read all available
            // data.
            dataStream.readNBytes(dataStream.available());
        } else {
            // The QUIC version needs to be parsed to determine the packet type, as the version
            // negotiation packet can only be identified by the version being 0.
            byte[] versionBytes = new byte[] {};
            QuicPacketType packetType;
            if (QuicPacketType.isLongHeaderPacket(firstByte)) {
                versionBytes = dataStream.readNBytes(QuicPacketByteLength.QUIC_VERSION_LENGTH);
                QuicVersion quicVersion = QuicVersion.getFromVersionBytes(versionBytes);
                if (quicVersion == QuicVersion.NULL_VERSION) {
                    packetType = QuicPacketType.VERSION_NEGOTIATION;
                } else {
                    packetType = QuicPacketType.getPacketTypeFromFirstByte(quicVersion, firstByte);
                    if (quicVersion != quicContext.getQuicVersion()
                            && packetType != QuicPacketType.VERSION_NEGOTIATION) {
                        LOGGER.warn("Received packet with unexpected QUIC version, ignoring it.");
                        packetType = QuicPacketType.UNKNOWN;
                    }
                }
            } else {
                packetType =
                        QuicPacketType.getPacketTypeFromFirstByte(
                                quicContext.getQuicVersion(), firstByte);
            }

            // Store the packet in the buffer for further processing.
            switch (packetType) {
                case INITIAL_PACKET:
                    receivedPacketBuffer
                            .get(packetType)
                            .add(readInitialPacket(firstByte, versionBytes, dataStream));
                    break;
                case HANDSHAKE_PACKET:
                    receivedPacketBuffer
                            .get(packetType)
                            .add(readHandshakePacket(firstByte, versionBytes, dataStream));
                    break;
                case ONE_RTT_PACKET:
                    receivedPacketBuffer
                            .get(packetType)
                            .add(readOneRTTPacket(firstByte, dataStream));
                    break;
                case ZERO_RTT_PACKET:
                    throw new UnsupportedOperationException("Unknown Packet - Not supported yet.");

                case RETRY_PACKET:
                    receivedPacketBuffer.get(packetType).add(readRetryPacket(dataStream));
                    break;
                case VERSION_NEGOTIATION:
                    receivedPacketBuffer
                            .get(packetType)
                            .add(readVersionNegotiationPacket(dataStream));
                    break;
                case UNKNOWN:
                    throw new UnsupportedOperationException("Unknown Packet - Not supported yet.");
                default:
                    break;
            }
        }

        // Iterate over the buffer to identify which packets can be decrypted. Decrypt initial
        // packets first, followed by handshake packets, and then application packets. Within each
        // type, decrypt the packet with the smallest packet number first.
        decryptInitialPacketsInBuffer();
        decryptHandshakePacketsInBuffer();
        decryptOneRRTPacketsInBuffer();

        // Pass the next possible packet to the upper layer ({@link QuicFrameLayer}) for further
        // processing.
        QuicPacketType packetTypeToProcess = getPacketTypeToProcessNext();
        if (packetTypeToProcess != null) {
            ArrayList<QuicPacket> packets = receivedPacketBuffer.get(packetTypeToProcess);
            QuicPacket packet = packets.remove(0);
            LOGGER.debug(
                    "Processing {} Packet: {}", packetTypeToProcess, packet.getPlainPacketNumber());
            receivedPacketBuffer.put(packetTypeToProcess, packets);

            outputStream.write(packet.getUnprotectedPayload().getValue());
            quicContext.getReceivedPackets().add(packet.getPacketType());
        }

        if (currentInputStream == null) {
            currentInputStream = new HintedLayerInputStream(null, this);
            currentInputStream.extendStream(outputStream.toByteArray());
        } else {
            currentInputStream.extendStream(outputStream.toByteArray());
        }

        outputStream.flush();
    }

    private byte[] writePacket(byte[] data, QuicPacket packet) throws CryptoException {
        packet.setUnprotectedPayload(data);
        return writePacket(packet);
    }

    private byte[] writePacket(QuicPacket packet) throws CryptoException {
        switch (packet.getPacketType()) {
            case INITIAL_PACKET:
                return writeInitialPacket((InitialPacket) packet);
            case HANDSHAKE_PACKET:
                return writeHandshakePacket((HandshakePacket) packet);
            case ONE_RTT_PACKET:
                return writeOneRTTPacket((OneRTTPacket) packet);
            case ZERO_RTT_PACKET:
                return writeZeroRTTPacket((ZeroRTTPacket) packet);
            case RETRY_PACKET:
                throw new UnsupportedOperationException("Retry Packet - Not supported yet.");
            case VERSION_NEGOTIATION:
                throw new UnsupportedOperationException(
                        "Version Negotiation Packet - Not supported yet.");
            case UNKNOWN:
                throw new UnsupportedOperationException("Unknown Packet - Not supported yet.");
            default:
                return null;
        }
    }

    private byte[] writeInitialPacket(InitialPacket packet) throws CryptoException {
        packet.getPreparator(context).prepare();
        encryptor.encryptInitialPacket(packet);
        packet.updateFlagsWithEncodedPacketNumber();
        encryptor.addHeaderProtectionInitial(packet);
        return packet.getSerializer(context).serialize();
    }

    private byte[] writeHandshakePacket(HandshakePacket packet) throws CryptoException {
        packet.getPreparator(context).prepare();
        encryptor.encryptHandshakePacket(packet);
        packet.updateFlagsWithEncodedPacketNumber();
        encryptor.addHeaderProtectionHandshake(packet);
        return packet.getSerializer(context).serialize();
    }

    private byte[] writeOneRTTPacket(OneRTTPacket packet) throws CryptoException {
        packet.getPreparator(context).prepare();
        encryptor.encryptOneRRTPacket(packet);
        packet.updateFlagsWithEncodedPacketNumber();
        encryptor.addHeaderProtectionOneRRT(packet);
        return packet.getSerializer(context).serialize();
    }

    private byte[] writeZeroRTTPacket(ZeroRTTPacket packet) throws CryptoException {
        packet.getPreparator(context).prepare();
        encryptor.encryptZeroRTTPacket(packet);
        packet.updateFlagsWithEncodedPacketNumber();
        encryptor.addHeaderProtectionZeroRTT(packet);
        return packet.getSerializer(context).serialize();
    }

    private InitialPacket readInitialPacket(
            int flags, byte[] versionBytes, InputStream dataStream) {
        InitialPacket packet = new InitialPacket(((byte) flags), versionBytes);
        packet.getParser(context, dataStream).parse(packet);
        return packet;
    }

    private InitialPacket decryptIntitialPacket(InitialPacket packet) throws CryptoException {
        decryptor.removeHeaderProtectionInitial(packet);
        packet.convertCompleteProtectedHeader();
        decryptor.decryptInitialPacket(packet);
        quicContext.addReceivedInitialPacketNumber(packet.getPlainPacketNumber());
        packet.getHandler(context).adjustContext(packet);
        addProducedContainer(packet);
        return packet;
    }

    private HandshakePacket readHandshakePacket(
            int flags, byte[] versionBytes, InputStream dataStream) {
        HandshakePacket packet = new HandshakePacket((byte) flags, versionBytes);
        packet.getParser(context, dataStream).parse(packet);
        return packet;
    }

    private HandshakePacket decryptHandshakePacket(HandshakePacket packet) throws CryptoException {
        decryptor.removeHeaderProtectionHandshake(packet);
        packet.convertCompleteProtectedHeader();
        decryptor.decryptHandshakePacket(packet);
        quicContext.addReceivedHandshakePacketNumber(packet.getPlainPacketNumber());
        packet.getHandler(context).adjustContext(packet);
        addProducedContainer(packet);
        return packet;
    }

    private OneRTTPacket readOneRTTPacket(int flags, InputStream dataStream) {
        OneRTTPacket packet = new OneRTTPacket((byte) flags);
        packet.getParser(context, dataStream).parse(packet);
        return packet;
    }

    private OneRTTPacket decryptOneRTTPacket(OneRTTPacket packet) throws CryptoException {
        decryptor.removeHeaderProtectionOneRTT(packet);
        packet.convertCompleteProtectedHeader();
        decryptor.decryptOneRTTPacket(packet);
        quicContext.addReceivedOneRTTPacketNumber(packet.getPlainPacketNumber());
        packet.getHandler(context).adjustContext(packet);
        addProducedContainer(packet);
        return packet;
    }

    private RetryPacket readRetryPacket(InputStream dataStream) {
        RetryPacket packet = new RetryPacket();
        packet.getParser(context, dataStream).parse(packet);
        packet.getHandler(context).adjustContext(packet);
        addProducedContainer(packet);
        return packet;
    }

    private VersionNegotiationPacket readVersionNegotiationPacket(InputStream dataStream) {
        VersionNegotiationPacket packet = new VersionNegotiationPacket();
        packet.getParser(context, dataStream).parse(packet);
        packet.getHandler(context).adjustContext(packet);
        addProducedContainer(packet);
        return packet;
    }

    private void decryptInitialPacketsInBuffer() {
        if (!receivedPacketBuffer.get(QuicPacketType.INITIAL_PACKET).isEmpty()
                && quicContext.isInitialSecretsInitialized()) {
            receivedPacketBuffer.computeIfPresent(
                    QuicPacketType.INITIAL_PACKET,
                    (packetType, packets) ->
                            (ArrayList<QuicPacket>)
                                    packets.stream()
                                            .map(
                                                    packet -> {
                                                        try {
                                                            return packet.getUnprotectedPayload()
                                                                            == null
                                                                    ? decryptIntitialPacket(
                                                                            (InitialPacket) packet)
                                                                    : packet;
                                                        } catch (CryptoException ex) {
                                                            throw new CryptoRuntimeException(
                                                                    "Could not decrypt packet", ex);
                                                        }
                                                    })
                                            .sorted(
                                                    Comparator.comparingInt(
                                                            QuicPacket::getPlainPacketNumber))
                                            .collect(Collectors.toList()));
        }
    }

    private void decryptHandshakePacketsInBuffer() {
        if (!receivedPacketBuffer.get(QuicPacketType.HANDSHAKE_PACKET).isEmpty()
                && quicContext.isHandshakeSecretsInitialized()) {
            receivedPacketBuffer.computeIfPresent(
                    QuicPacketType.HANDSHAKE_PACKET,
                    (packetType, packets) ->
                            (ArrayList<QuicPacket>)
                                    packets.stream()
                                            .map(
                                                    packet -> {
                                                        try {
                                                            return packet.getUnprotectedPayload()
                                                                            == null
                                                                    ? decryptHandshakePacket(
                                                                            (HandshakePacket)
                                                                                    packet)
                                                                    : packet;
                                                        } catch (CryptoException ex) {
                                                            throw new CryptoRuntimeException(
                                                                    "Could not decrypt packet", ex);
                                                        }
                                                    })
                                            .sorted(
                                                    Comparator.comparingInt(
                                                            QuicPacket::getPlainPacketNumber))
                                            .collect(Collectors.toList()));
        }
    }

    private void decryptOneRRTPacketsInBuffer() {
        if (!receivedPacketBuffer.get(QuicPacketType.ONE_RTT_PACKET).isEmpty()
                && quicContext.isApplicationSecretsInitialized()) {
            receivedPacketBuffer.computeIfPresent(
                    QuicPacketType.ONE_RTT_PACKET,
                    (packetType, packets) ->
                            (ArrayList<QuicPacket>)
                                    packets.stream()
                                            .map(
                                                    packet -> {
                                                        try {
                                                            return packet.getUnprotectedPayload()
                                                                            == null
                                                                    ? decryptOneRTTPacket(
                                                                            (OneRTTPacket) packet)
                                                                    : packet;
                                                        } catch (CryptoException ex) {
                                                            throw new CryptoRuntimeException(
                                                                    "Could not decrypt packet", ex);
                                                        }
                                                    })
                                            .sorted(
                                                    Comparator.comparingInt(
                                                            QuicPacket::getPlainPacketNumber))
                                            .collect(Collectors.toList()));
        }
    }

    private QuicPacketType getPacketTypeToProcessNext() {
        if (!receivedPacketBuffer.get(QuicPacketType.INITIAL_PACKET).isEmpty()
                && quicContext.isInitialSecretsInitialized()
                && !quicContext.isHandshakeSecretsInitialized()) {
            return QuicPacketType.INITIAL_PACKET;
        } else if (!receivedPacketBuffer.get(QuicPacketType.HANDSHAKE_PACKET).isEmpty()
                && quicContext.isHandshakeSecretsInitialized()
                && !quicContext.isApplicationSecretsInitialized()) {
            return QuicPacketType.HANDSHAKE_PACKET;
        } else if (!receivedPacketBuffer.get(QuicPacketType.ONE_RTT_PACKET).isEmpty()
                && quicContext.isApplicationSecretsInitialized()) {
            return QuicPacketType.ONE_RTT_PACKET;
        }
        return null;
    }

    /** Checks if the packet contains (unencrypted) payload. */
    private boolean isEmptyPacket(QuicPacket packet) {
        return !context.getConfig().isUseAllProvidedQuicPackets()
                && packet.getUnprotectedPayload() != null
                && packet.getUnprotectedPayload().getValue().length == 0;
    }

    @Override
    public void sendAck(byte[] data) {
        context.setTalkingConnectionEndType(context.getConnection().getLocalConnectionEndType());
        try {
            if (quicContext.getReceivedPackets().getLast() == QuicPacketType.INITIAL_PACKET) {
                getLowerLayer().sendData(null, writePacket(data, new InitialPacket()));
            } else if (quicContext.getReceivedPackets().getLast()
                    == QuicPacketType.HANDSHAKE_PACKET) {
                getLowerLayer().sendData(null, writePacket(data, new HandshakePacket()));
            } else if (quicContext.getReceivedPackets().getLast()
                    == QuicPacketType.ONE_RTT_PACKET) {
                getLowerLayer().sendData(null, writePacket(data, new OneRTTPacket()));
            }
        } catch (IOException | CryptoException e) {
            LOGGER.error("Could not send ACK", e);
        }
        context.setTalkingConnectionEndType(
                context.getConnection().getLocalConnectionEndType().getPeer());
    }

    /** Clears the packet buffer. This function is typically used when resetting the connection. */
    public void clearReceivedPacketBuffer() {
        receivedPacketBuffer.values().forEach(ArrayList::clear);
    }
}
