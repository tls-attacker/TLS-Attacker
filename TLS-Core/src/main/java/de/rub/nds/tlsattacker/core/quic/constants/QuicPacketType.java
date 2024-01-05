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
    UNKNOWN((byte) 255, 255),
    INITIAL_PACKET((byte) 0, 0xc0),
    ZERO_RTT_PACKET((byte) 1, 0xd0),
    HANDSHAKE_PACKET((byte) 2, 0xe0),
    RETRY_PACKET((byte) 3, 0xf0),
    ONE_RTT_PACKET((byte) 255, 0x80),
    VERSION_NEGOTIATION((byte) 0, 0x20),
    UDP_PADDING((byte) 0, 0x00);

    private final int value;
    private final int header;
    private static final Map<Byte, QuicPacketType> MAP;

    QuicPacketType(byte value, int header) {
        this.value = value;
        this.header = header;
    }

    static {
        MAP = new HashMap<>();
        for (QuicPacketType cm : QuicPacketType.values()) {
            if (cm == UNKNOWN) {
                continue;
            }
            MAP.put((byte) cm.header, cm);
        }
    }

    public static QuicPacketType getPacketTypeFromFirstByte(int firstByte) {
        if (isShortHeaderPacket(firstByte)) {
            // ONE_RTT_PACKETS are the only short header packets
            return ONE_RTT_PACKET;
        } else {
            // long header packet
            QuicPacketType type = MAP.get((byte) (firstByte & 0b11110000));
            if (type != null) {
                return type;
            } else {
                return UNKNOWN;
            }
        }
    }

    public static QuicPacketType getPacketType(byte value) {
        QuicPacketType type = MAP.get(value);
        if (type == null) {
            type = UNKNOWN;
        }
        return type;
    }

    public static boolean isLongHeaderPacket(int firstByte) {
        return !isShortHeaderPacket(firstByte);
    }

    public static boolean isShortHeaderPacket(int firstByte) {
        return (firstByte & 0b10000000) == 0b00000000;
    }

    public byte getValue() {
        return (byte) value;
    }

    public byte getHeader() {
        return (byte) header;
    }

    public String getName() {
        return this.name();
    }
}
