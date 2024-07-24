/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.exceptions.CryptoRuntimeException;
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
import de.rub.nds.tlsattacker.core.quic.parser.packet.HandshakePacketParser;
import de.rub.nds.tlsattacker.core.quic.parser.packet.InitialPacketParser;
import de.rub.nds.tlsattacker.core.quic.parser.packet.OneRTTPacketParser;
import de.rub.nds.tlsattacker.core.quic.parser.packet.RetryPacketParser;
import de.rub.nds.tlsattacker.core.quic.parser.packet.VersionNegotiationPacketParser;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.HandshakePacketPreparator;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.InitialPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.OneRTTPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.preparator.packet.ZeroRTTPacketPreparator;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.HandshakePacketSerializer;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.InitialPacketSerializer;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.OneRTTPacketSerializer;
import de.rub.nds.tlsattacker.core.quic.serializer.packet.ZeroRTTPacketSerializer;
import de.rub.nds.tlsattacker.core.state.quic.QuicContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class QuicPacketLayer extends AcknowledgingProtocolLayer<QuicPacketLayerHint, QuicPacket> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final QuicContext context;

    private final QuicDecryptor decryptor;
    private final QuicEncryptor encryptor;

    private final Map<QuicPacketType, ArrayList<QuicPacket>> receivedPacketBuffer = new HashMap<>();

    public QuicPacketLayer(QuicContext context) {
        super(ImplementedLayers.QUICPACKET);
        this.context = context;
        decryptor = new QuicDecryptor(context);
        encryptor = new QuicEncryptor(context);
        Arrays.stream(QuicPacketType.values())
                .forEach(
                        quicPacketType ->
                                receivedPacketBuffer.put(quicPacketType, new ArrayList<>()));
    }

    public void clearReceivedPacketBuffer() {
        receivedPacketBuffer.values().forEach(ArrayList::clear);
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<QuicPacket> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (QuicPacket p : configuration.getContainerList()) {
                if (p.getProtectedPayload().getValue() != null) {
                    switch (p.getPacketType()) {
                        case INITIAL_PACKET:
                        case HANDSHAKE_PACKET:
                        case ONE_RTT_PACKET:
                        case ZERO_RTT_PACKET:
                            getLowerLayer().sendData(null, p.getSerializer(context).serialize());
                            LOGGER.debug("Send {}", p.getPacketType().getName());
                            break;
                        case RETRY_PACKET:
                            throw new UnsupportedOperationException(
                                    "Retry Packet - Not supported yet.");
                        case UNKNOWN:
                            throw new UnsupportedOperationException(
                                    "Unknown Packet - Not supported yet.");
                        default:
                            break;
                    }
                } else {
                    LOGGER.error("Can not send configured packet as it is not encrypted yet.");
                }
            }
            setLayerConfiguration(null);
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult sendData(QuicPacketLayerHint hint, byte[] data)
            throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        LayerConfiguration<QuicPacket> configuration = getLayerConfiguration();
        try {
            if (hint != null && hint.getQuicPacketType() != null) {
                switch (hint.getQuicPacketType()) {
                    case INITIAL_PACKET:
                        InitialPacket initialPacket = new InitialPacket();
                        stream.writeBytes(writeInitialPacket(data, initialPacket));
                        LOGGER.debug("Send initial packet");
                        break;
                    case HANDSHAKE_PACKET:
                        HandshakePacket handshakePacket = new HandshakePacket();
                        stream.writeBytes(writeHandshakePacket(data, handshakePacket));
                        LOGGER.debug("Send handshake packet");
                        break;
                    case ONE_RTT_PACKET:
                        OneRTTPacket oneRTTPacket = new OneRTTPacket();
                        stream.writeBytes(writeOneRTTPacket(data, oneRTTPacket));
                        LOGGER.debug("Send one rtt packet");
                        break;
                    case ZERO_RTT_PACKET:
                        ZeroRTTPacket zeroRTTPacket = new ZeroRTTPacket();
                        stream.writeBytes(writeZeroRTTPacket(data, zeroRTTPacket));
                        LOGGER.debug("Send zero rtt packet");
                        break;
                }
                getLowerLayer().sendData(null, stream.toByteArray());
                stream.flush();
                setLayerConfiguration(null);
            } else if (configuration != null && configuration.getContainerList() != null) {
                for (QuicPacket p : configuration.getContainerList()) {
                    switch (p.getPacketType()) {
                        case INITIAL_PACKET:
                            stream.writeBytes(writeInitialPacket(data, (InitialPacket) p));
                            break;
                        case HANDSHAKE_PACKET:
                            stream.writeBytes(writeHandshakePacket(data, (HandshakePacket) p));
                            break;
                        case ONE_RTT_PACKET:
                            stream.writeBytes(writeOneRTTPacket(data, (OneRTTPacket) p));
                            break;
                        case ZERO_RTT_PACKET:
                            stream.writeBytes(writeZeroRTTPacket(data, (ZeroRTTPacket) p));
                        case RETRY_PACKET:
                            throw new UnsupportedOperationException(
                                    "Retry Packet - Not supported yet.");
                        case UNKNOWN:
                            throw new UnsupportedOperationException(
                                    "Unknown Packet - Not supported yet.");

                        default:
                            break;
                    }
                }
                getLowerLayer().sendData(null, stream.toByteArray());
                stream.flush();
                setLayerConfiguration(null);
            }
        } catch (CryptoException e) {
            LOGGER.error("Could not send data: ", e);
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult receiveData() {
        LOGGER.debug("Receive Data");
        try {
            InputStream dataStream = getLowerLayer().getDataStream();
            readPackets(dataStream);

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
        readPackets(dataStream);
    }

    private void readPackets(InputStream dataStream) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        /*
         Long Header Packet:
           Header Form (1) = 1,
           Fixed Bit (1) = 1,
           Long Packet Type (2),
           Type-Specific Bits (4),
         Short Header Packet:
           Header Form (1) = 0,
           Fixed Bit (1) = 1,
           Spin Bit (1),
           Reserved Bits (2),
           Key Phase (1),
        */
        // read all packets in one udp datagram and add to buffer
        int firstByte = dataStream.read();

        // if the first byte is 0 -> UDP padding
        if (firstByte == 0x00) {
            // read all available data
            dataStream.readNBytes(dataStream.available());
        } else {
            // the quic version needs to be parsed to determine the packet type as the version
            // negotiation packet can only be identified by the version being 0
            byte[] versionBytes = new byte[] {};
            QuicPacketType packetType;
            if (QuicPacketType.isLongHeaderPacket(firstByte)) {
                versionBytes = dataStream.readNBytes(QuicPacketByteLength.QUIC_VERSION_LENGTH);
                QuicVersion quicVersion = QuicVersion.getFromVersionBytes(versionBytes);
                if (quicVersion == QuicVersion.NULL_VERSION) {
                    packetType = QuicPacketType.VERSION_NEGOTIATION;
                } else {
                    packetType = QuicPacketType.getPacketTypeFromFirstByte(quicVersion, firstByte);

                    if (quicVersion != context.getQuicVersion()
                            && packetType != QuicPacketType.VERSION_NEGOTIATION) {
                        LOGGER.error("Received packet with unexpected version, ignoring it.");
                        packetType = QuicPacketType.UNKNOWN;
                    }
                }
            } else {
                packetType =
                        QuicPacketType.getPacketTypeFromFirstByte(
                                context.getQuicVersion(), firstByte);
            }

            LOGGER.debug("Read {}", packetType);

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
                case RETRY_PACKET:
                    readRetryPacket(dataStream);
                    break;
                case ONE_RTT_PACKET:
                    receivedPacketBuffer
                            .get(packetType)
                            .add(readOneRTTPacket(firstByte, dataStream));
                    break;
                case VERSION_NEGOTIATION:
                    readVersionNegotiationPacket(dataStream);
                    break;
                default:
                    break;
            }
        }
        try {
            // go over buffer, check which packets can be decrypted, decrypt initial packets first
            // then
            // handshake then application packets, decrypt packet with smallest packet number first
            if (!receivedPacketBuffer.get(QuicPacketType.INITIAL_PACKET).isEmpty()
                    && context.isInitialSecretsInitialized()) {
                // decrypt encrypted packets and sort by packet number
                receivedPacketBuffer.computeIfPresent(
                        QuicPacketType.INITIAL_PACKET,
                        (k, v) ->
                                (ArrayList<QuicPacket>)
                                        v.stream()
                                                .map(
                                                        p -> {
                                                            try {
                                                                return p.getUnprotectedPayload()
                                                                                == null
                                                                        ? decryptIntitialPacket(
                                                                                (InitialPacket) p)
                                                                        : p;
                                                            } catch (CryptoException e) {
                                                                throw new CryptoRuntimeException(e);
                                                            }
                                                        })
                                                .sorted(
                                                        Comparator.comparingInt(
                                                                QuicPacket::getPlainPacketNumber))
                                                .collect(Collectors.toList()));
            }
            if (!receivedPacketBuffer.get(QuicPacketType.HANDSHAKE_PACKET).isEmpty()
                    && context.isHandshakeSecretsInitialized()) {
                // decrypt encrypted packets and sort by packet number
                receivedPacketBuffer.computeIfPresent(
                        QuicPacketType.HANDSHAKE_PACKET,
                        (k, v) ->
                                (ArrayList<QuicPacket>)
                                        v.stream()
                                                .map(
                                                        p -> {
                                                            try {
                                                                return p.getUnprotectedPayload()
                                                                                == null
                                                                        ? decryptHandshakePacket(
                                                                                (HandshakePacket) p)
                                                                        : p;
                                                            } catch (CryptoException e) {
                                                                throw new CryptoRuntimeException(e);
                                                            }
                                                        })
                                                .sorted(
                                                        Comparator.comparingInt(
                                                                QuicPacket::getPlainPacketNumber))
                                                .collect(Collectors.toList()));
            }
            if (!receivedPacketBuffer.get(QuicPacketType.ONE_RTT_PACKET).isEmpty()
                    && context.isApplicationSecretsInitialized()) {
                // decrypt encrypted packets and sort by packet number
                receivedPacketBuffer.computeIfPresent(
                        QuicPacketType.ONE_RTT_PACKET,
                        (k, v) ->
                                (ArrayList<QuicPacket>)
                                        v.stream()
                                                .map(
                                                        p -> {
                                                            try {
                                                                return p.getUnprotectedPayload()
                                                                                == null
                                                                        ? decryptOneRTTPacket(
                                                                                (OneRTTPacket) p)
                                                                        : p;
                                                            } catch (CryptoException e) {
                                                                throw new CryptoRuntimeException(e);
                                                            }
                                                        })
                                                .sorted(
                                                        Comparator.comparingInt(
                                                                QuicPacket::getPlainPacketNumber))
                                                .collect(Collectors.toList()));
            }

            LOGGER.debug(
                    "Packet Buffer: {}",
                    receivedPacketBuffer.entrySet().stream()
                            .filter(e -> !e.getValue().isEmpty())
                            .map(
                                    e ->
                                            e.getKey()
                                                    + ": "
                                                    + e.getValue().stream()
                                                            .map(QuicPacket::getPlainPacketNumber)
                                                            .collect(Collectors.toList()))
                            .collect(Collectors.joining(",\n")));

            QuicPacketType packetTypeToProcess = getPacketTypeToProcessNext();

            if (packetTypeToProcess != null) {
                ArrayList<QuicPacket> packets = receivedPacketBuffer.get(packetTypeToProcess);
                QuicPacket packet = packets.remove(0);
                LOGGER.debug(
                        "Processing {} Packet: {}",
                        packetTypeToProcess,
                        packet.getPlainPacketNumber());
                receivedPacketBuffer.put(packetTypeToProcess, packets);

                outputStream.write(packet.getUnprotectedPayload().getValue());
                context.getReceivedPackets().add(packet.getPacketType());
            }

        } catch (CryptoRuntimeException e) {
            LOGGER.error("Could not decrypt packet", e);
        }

        if (currentInputStream == null) {
            currentInputStream = new HintedLayerInputStream(null, this);
            currentInputStream.extendStream(outputStream.toByteArray());
        } else {
            currentInputStream.extendStream(outputStream.toByteArray());
        }
        outputStream.flush();
    }

    private QuicPacketType getPacketTypeToProcessNext() {
        if (!receivedPacketBuffer.get(QuicPacketType.INITIAL_PACKET).isEmpty()
                && context.isInitialSecretsInitialized()
                && !context.isHandshakeSecretsInitialized()) {
            return QuicPacketType.INITIAL_PACKET;
        } else if (!receivedPacketBuffer.get(QuicPacketType.HANDSHAKE_PACKET).isEmpty()
                && context.isHandshakeSecretsInitialized()
                && !context.isApplicationSecretsInitialized()) {
            return QuicPacketType.HANDSHAKE_PACKET;
        } else if (!receivedPacketBuffer.get(QuicPacketType.ONE_RTT_PACKET).isEmpty()
                && context.isApplicationSecretsInitialized()) {
            return QuicPacketType.ONE_RTT_PACKET;
        }
        return null;
    }

    public byte[] writeInitialPacket(byte[] data, InitialPacket packet) throws CryptoException {
        packet.setUnprotectedPayload(data);

        InitialPacketSerializer packetSerializer = packet.getSerializer(context);
        InitialPacketPreparator preparator = packet.getPreparator(context);
        preparator.prepare();

        encryptor.encryptInitialPacket(packet);
        packet.updateFlagsWithEncodedPacketNumber();
        encryptor.addHeaderProtectionInitial(packet);
        addProducedContainer(packet);
        return packetSerializer.serialize();
    }

    public byte[] writeHandshakePacket(byte[] data, HandshakePacket packet) throws CryptoException {
        packet.setUnprotectedPayload(data);

        HandshakePacketSerializer packetSerializer = packet.getSerializer(context);
        HandshakePacketPreparator preparator = packet.getPreparator(context);
        preparator.prepare();

        encryptor.encryptHandshakePacket(packet);
        packet.updateFlagsWithEncodedPacketNumber();
        encryptor.addHeaderProtectionHandshake(packet);
        addProducedContainer(packet);
        return packetSerializer.serialize();
    }

    public byte[] writeOneRTTPacket(byte[] data, OneRTTPacket packet) throws CryptoException {
        packet.setUnprotectedPayload(data);

        OneRTTPacketSerializer packetSerializer = packet.getSerializer(context);
        OneRTTPacketPreparator preparator = packet.getPreparator(context);
        preparator.prepare();

        encryptor.encryptApplicationPacket(packet);
        packet.updateFlagsWithEncodedPacketNumber();
        encryptor.addHeaderProtectionApplication(packet);
        addProducedContainer(packet);
        return packetSerializer.serialize();
    }

    public byte[] writeZeroRTTPacket(byte[] data, ZeroRTTPacket packet) throws CryptoException {
        packet.setUnprotectedPayload(data);

        ZeroRTTPacketSerializer packetSerializer = packet.getSerializer(context);
        ZeroRTTPacketPreparator preparator = packet.getPreparator(context);
        preparator.prepare();

        encryptor.encryptZeroRTTPacket(packet);
        packet.updateFlagsWithEncodedPacketNumber();
        encryptor.addHeaderProtectionZeroRTT(packet);
        addProducedContainer(packet);
        return packetSerializer.serialize();
    }

    public InitialPacket readInitialPacket(int flags, byte[] versionBytes, InputStream dataStream) {
        InitialPacket packet = new InitialPacket(((byte) flags), versionBytes);
        InitialPacketParser parser = packet.getParser(context, dataStream);
        parser.parse(packet);
        return packet;
    }

    public InitialPacket decryptIntitialPacket(InitialPacket packet) throws CryptoException {
        decryptor.removeHeaderProtection(packet);
        packet.convertCompleteProtectedHeader();
        decryptor.decryptInitialPacket(packet);
        context.addReceivedInitialPacketNumber(packet.getPlainPacketNumber());
        addProducedContainer(packet);
        return packet;
    }

    public HandshakePacket readHandshakePacket(
            int flags, byte[] versionBytes, InputStream dataStream) {
        HandshakePacket packet = new HandshakePacket((byte) flags, versionBytes);
        HandshakePacketParser parser = packet.getParser(context, dataStream);
        parser.parse(packet);
        return packet;
    }

    public HandshakePacket decryptHandshakePacket(HandshakePacket packet) throws CryptoException {
        decryptor.removeHeaderProtection(packet);
        packet.convertCompleteProtectedHeader();
        decryptor.decryptHandshakePacket(packet);
        context.addReceivedHandshakePacketNumber(packet.getPlainPacketNumber());
        addProducedContainer(packet);
        return packet;
    }

    public OneRTTPacket readOneRTTPacket(int flags, InputStream dataStream) {
        OneRTTPacket packet = new OneRTTPacket((byte) flags);
        OneRTTPacketParser parser = packet.getParser(context, dataStream);
        parser.parse(packet);
        return packet;
    }

    public VersionNegotiationPacket readVersionNegotiationPacket(InputStream dataStream) {
        VersionNegotiationPacket packet = new VersionNegotiationPacket();
        VersionNegotiationPacketParser parser = packet.getParser(context, dataStream);
        parser.parse(packet);
        packet.getHandler(context).adjustContext(packet);
        addProducedContainer(packet);
        LOGGER.info(
                "Read VN packet, supported versions: {}",
                packet.getSupportedVersions().stream()
                        .map(
                                v ->
                                        QuicVersion.getVersionNameFromBytes(v)
                                                + " ("
                                                + ArrayConverter.bytesToHexString(v)
                                                + ")")
                        .collect(Collectors.toList()));
        return packet;
    }

    public OneRTTPacket decryptOneRTTPacket(OneRTTPacket packet) throws CryptoException {
        decryptor.removeHeaderProtection(packet);
        packet.convertCompleteProtectedHeader();
        decryptor.decryptApplicationPacket(packet);
        context.addReceivedOneRTTPacketNumber(packet.getPlainPacketNumber());
        addProducedContainer(packet);
        return packet;
    }

    public RetryPacket readRetryPacket(InputStream dataStream) {
        RetryPacket packet = new RetryPacket();
        RetryPacketParser parser = packet.getParser(context, dataStream);
        parser.parse(packet);
        packet.getHandler(context).adjustContext(packet);
        addProducedContainer(packet);
        return packet;
    }

    @Override
    public void sendAck(byte[] data) {
        context.setTalkingConnectionEndType(context.getConnection().getLocalConnectionEndType());
        try {
            if (context.getReceivedPackets().getLast() == QuicPacketType.INITIAL_PACKET) {
                getLowerLayer().sendData(null, writeInitialPacket(data, new InitialPacket()));
            } else if (context.getReceivedPackets().getLast() == QuicPacketType.HANDSHAKE_PACKET) {
                getLowerLayer().sendData(null, writeHandshakePacket(data, new HandshakePacket()));
            } else if (context.getReceivedPackets().getLast() == QuicPacketType.ONE_RTT_PACKET) {
                getLowerLayer().sendData(null, writeOneRTTPacket(data, new OneRTTPacket()));
            }
        } catch (IOException | CryptoException e) {
            LOGGER.error("Could not send ACK", e);
        }
        context.setTalkingConnectionEndType(
                context.getConnection().getLocalConnectionEndType().getPeer());
    }
}
