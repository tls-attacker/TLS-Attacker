/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public enum QuicPacketType {
    UNKNOWN(255, 255),
    INITIAL_PACKET(0xc0, 0xd0),
    ZERO_RTT_PACKET(0xd0, 0xe0),
    HANDSHAKE_PACKET(0xe0, 0xf0),
    RETRY_PACKET(0xf0, 0xc0),
    ONE_RTT_PACKET(0x40, 0x40),
    VERSION_NEGOTIATION(0x80, 0x80),
    STATELESS_RESET(0xfe, 0xfe);

    private static final Map<Byte, QuicPacketType> QUIC1_MAP;
    private static final Map<Byte, QuicPacketType> QUIC2_MAP;

    private final byte headerQuic1;
    private final byte headerQuic2;

    QuicPacketType(int headerQuic1, int headerQuic2) {
        this.headerQuic1 = (byte) headerQuic1;
        this.headerQuic2 = (byte) headerQuic2;
    }

    static {
        QUIC1_MAP = new HashMap<>();
        QUIC2_MAP = new HashMap<>();
        for (QuicPacketType type : QuicPacketType.values()) {
            if (type == UNKNOWN || type == VERSION_NEGOTIATION || type == STATELESS_RESET) {
                continue;
            }
            QUIC1_MAP.put(type.headerQuic1, type);
            QUIC2_MAP.put(type.headerQuic2, type);
        }
    }

    public static QuicPacketType getPacketTypeFromFirstByte(QuicVersion version, int firstByte) {
        if (version == QuicVersion.NULL_VERSION) {
            return VERSION_NEGOTIATION;
        }
        if (!version.isSupported()) {
            return UNKNOWN;
        }
        if (isShortHeaderPacket(firstByte)) {
            // 1-RTT packets are the only short header packets in all supported versions
            return ONE_RTT_PACKET;
        }
        QuicPacketType type =
                getHeaderMap(version).get((byte) (firstByte & 0b1111_0000 | 0b0100_0000));
        return Objects.requireNonNullElse(type, UNKNOWN);
    }

    public static boolean isLongHeaderPacket(int firstByte) {
        return !isShortHeaderPacket(firstByte);
    }

    public static boolean isShortHeaderPacket(int firstByte) {
        return (firstByte & 0b10000000) == 0b00000000;
    }

    public boolean isFrameContainer() {
        return switch (this) {
            case INITIAL_PACKET, ZERO_RTT_PACKET, HANDSHAKE_PACKET, ONE_RTT_PACKET -> true;
            case UNKNOWN, VERSION_NEGOTIATION, RETRY_PACKET, STATELESS_RESET -> false;
        };
    }

    public byte getHeader(QuicVersion version) {
        return switch (version) {
            case VERSION_1, DRAFT_29, DRAFT_30, DRAFT_31, DRAFT_32, DRAFT_33, DRAFT_34 ->
                    headerQuic1;
            case VERSION_2 -> headerQuic2;
            case UNKNOWN, NEGOTIATION_VERSION, NULL_VERSION ->
                    throw new UnsupportedOperationException();
        };
    }

    private static Map<Byte, QuicPacketType> getHeaderMap(QuicVersion version) {
        return switch (version) {
            case VERSION_1, DRAFT_29, DRAFT_30, DRAFT_31, DRAFT_32, DRAFT_33, DRAFT_34 -> QUIC1_MAP;
            case VERSION_2 -> QUIC2_MAP;
            case UNKNOWN, NEGOTIATION_VERSION, NULL_VERSION ->
                    throw new UnsupportedOperationException();
        };
    }

    public String getName() {
        return this.name();
    }
}
