/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.quic.constants;

import de.rub.nds.modifiablevariable.util.DataConverter;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public enum QuicVersion {
    VERSION_1(0x00000001, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    VERSION_2(0x6b3343cf, "0dede3def700a6db819381be6e269dcbf9bd2ed9"),
    NEGOTIATION_VERSION(0x0a0a0a0a, "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    NULL_VERSION(0x00000000, ""),
    UNKNOWN(0xffffffff, "");

    private final int value;

    private final byte[] byteValue;

    private final byte[] initialSalt;

    private static final Map<Integer, QuicVersion> MAP;

    static {
        MAP = new HashMap<>();
        for (QuicVersion cm : QuicVersion.values()) {
            MAP.put(cm.getValue(), cm);
        }
    }

    QuicVersion(int value, String initialSalt) {
        this.value = value;
        this.byteValue = ByteBuffer.allocate(4).putInt(value).array();
        this.initialSalt = DataConverter.hexStringToByteArray(initialSalt);
    }

    public static QuicVersion getFromVersionBytes(byte[] versionBytes) {
        int versionValue = DataConverter.bytesToInt(versionBytes);
        return MAP.getOrDefault(versionValue, UNKNOWN);
    }

    public static String getVersionNameFromBytes(byte[] versionBytes) {
        int versionValue = DataConverter.bytesToInt(versionBytes);
        QuicVersion version = MAP.get(versionValue);
        if (version != null) {
            return version.getName();
        } else {
            if (versionValue >= 0x51303000 && versionValue <= 0x51303fff) {
                return "GOOGLE_QUIC_" + new String(versionBytes, StandardCharsets.UTF_8);
            } else if (versionValue >= 0x54303000 && versionValue <= 0x54303fff) {
                return "GOOGLE_QUIC_TLS_" + new String(versionBytes, StandardCharsets.UTF_8);
            } else if (versionValue >= 0x5c100000 && versionValue <= 0x5c10000f) {
                return "QUIC_OVER_SCION";
            } else if (versionValue >= 0x51474f00 && versionValue <= 0x51474fff) {
                return "QGO_" + versionBytes[3];
            } else if (versionValue >= 0x91c17000 && versionValue <= 0x91c170ff) {
                return "QICLY0_" + versionBytes[3];
            } else if (versionValue >= 0xabcd0000 && versionValue <= 0xabcd000f) {
                return "MSQUIC";
            } else if (versionValue >= 0xf123f0c0 && versionValue <= 0xf123f0cf) {
                return "MOZQUIC";
            } else if (versionValue >= 0xfaceb000 && versionValue <= 0xfaceb00f) {
                return "MVFST";
            } else if (versionValue >= 0x07007000 && versionValue <= 0x0700700f) {
                return "TENCENTQUIC";
            } else if (versionValue >= 0x45474700 && versionValue <= 0x454747ff) {
                return "QUANT";
            } else if (versionValue == 0x50435130) {
                return "PICOQUIC";
            } else if (versionValue == 0x50524f58) {
                return "GOOGLE_QUIC_PROX";
            } else {
                return "UNKNOWN";
            }
        }
    }

    public int getValue() {
        return value;
    }

    public byte[] getByteValue() {
        return byteValue;
    }

    public byte[] getInitialSalt() {
        return initialSalt;
    }

    public String getKeyLabel() {
        return switch (this) {
            case VERSION_1 -> QuicHKDFConstants.QUIC1_KEY;
            case VERSION_2 -> QuicHKDFConstants.QUIC2_KEY;
            default -> throw new UnsupportedOperationException();
        };
    }

    public String getIvLabel() {
        return switch (this) {
            case VERSION_1 -> QuicHKDFConstants.QUIC1_IV;
            case VERSION_2 -> QuicHKDFConstants.QUIC2_IV;
            default -> throw new UnsupportedOperationException();
        };
    }

    public String getHeaderProtectionLabel() {
        return switch (this) {
            case VERSION_1 -> QuicHKDFConstants.QUIC1_HP;
            case VERSION_2 -> QuicHKDFConstants.QUIC2_HP;
            default -> throw new UnsupportedOperationException();
        };
    }

    public String getKeyUpdateLabel() {
        return switch (this) {
            case VERSION_1 -> QuicHKDFConstants.QUIC1_KU;
            case VERSION_2 -> QuicHKDFConstants.QUIC2_KU;
            default -> throw new UnsupportedOperationException();
        };
    }

    public String getName() {
        return this.name();
    }
}
