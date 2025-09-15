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

public enum QuicPacketType {
    UNKNOWN(255, 255),
    INITIAL_PACKET(0xc0, 0xd0),
    ZERO_RTT_PACKET(0xd0, 0xe0),
    HANDSHAKE_PACKET(0xe0, 0xf0),
    RETRY_PACKET(0xf0, 0xc0),
    ONE_RTT_PACKET(0x80, 0x80),
    VERSION_NEGOTIATION(0x20, 0x20),
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
            if (type == UNKNOWN) {
                continue;
            }
            QUIC1_MAP.put(type.headerQuic1, type);
            QUIC2_MAP.put(type.headerQuic2, type);
        }
    }

    public static QuicPacketType getPacketTypeFromFirstByte(QuicVersion version, int firstByte) {
        if (isShortHeaderPacket(firstByte)) {
            // 1-RTT packets are the only short header packets
            return ONE_RTT_PACKET;
        } else {
            QuicPacketType type = getHeaderMap(version).get((byte) (firstByte & 0b11110000));
            if (type != null) {
                return type;
            } else {
                return UNKNOWN;
            }
        }
    }

    public static boolean isLongHeaderPacket(int firstByte) {
        return !isShortHeaderPacket(firstByte);
    }

    public static boolean isShortHeaderPacket(int firstByte) {
        return (firstByte & 0b10000000) == 0b00000000;
    }

    public byte getHeader(QuicVersion version) {
        switch (version) {
            case VERSION_1:
                return headerQuic1;
            case VERSION_2:
                return headerQuic2;
            default:
                throw new UnsupportedOperationException();
        }
    }

    private static Map<Byte, QuicPacketType> getHeaderMap(QuicVersion version) {
        switch (version) {
            case VERSION_1:
                return QUIC1_MAP;
            case VERSION_2:
                return QUIC2_MAP;
            default:
                throw new UnsupportedOperationException();
        }
    }

    public String getName() {
        return this.name();
    }
}
