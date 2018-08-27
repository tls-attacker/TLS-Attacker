/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * RFC5764
 */
public enum SrtpProtectionProfiles {
    SRTP_AES128_CM_HMAC_SHA1_80(new byte[] { 0x00, 0x01 }),
    SRTP_AES128_CM_HMAC_SHA1_32(new byte[] { 0x00, 0x02 }),
    SRTP_NULL_HMAC_SHA1_80(new byte[] { 0x00, 0x05 }),
    SRTP_NULL_HMAC_SHA1_32(new byte[] { 0x00, 0x06 });

    private final byte[] srtpProtectionProfiles;
    private static final Map<Integer, SrtpProtectionProfiles> MAP;

    private static final Logger LOGGER = LogManager.getLogger();

    private SrtpProtectionProfiles(byte[] value) {
        this.srtpProtectionProfiles = value;
    }

    static {
        MAP = new HashMap<>();
        for (SrtpProtectionProfiles c : SrtpProtectionProfiles.values()) {
            MAP.put(ArrayConverter.bytesToInt(c.srtpProtectionProfiles), c);
        }
    }

    public byte[] getByteValue() {
        return srtpProtectionProfiles;
    }

    public static SrtpProtectionProfiles getProfileByType(byte[] value) {
        return MAP.get(ArrayConverter.bytesToInt(value));
    }

    public static List<SrtpProtectionProfiles> getProfilesAsArrayList(byte[] value) {
        List<SrtpProtectionProfiles> profileList = new ArrayList<>();

        for (int i = 0; i < value.length; i += 2) {
            if (i + 1 < value.length) {
                profileList.add(SrtpProtectionProfiles.getProfileByType(new byte[] { value[i], value[i + 1] }));
            } else {
                LOGGER.warn("value cannot be converted into an SrtpProtectionProfile - not enough bytes left");
            }
        }

        return profileList;
    }

    public byte getMinor() {
        return srtpProtectionProfiles[0];
    }

    public byte getMajor() {
        return srtpProtectionProfiles[1];
    }
}
