/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

import de.rub.nds.modifiablevariable.util.DataConverter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** RFC5764 */
public enum SrtpProtectionProfile {
    SRTP_AES128_CM_HMAC_SHA1_80(new byte[] {0x00, 0x01}),
    SRTP_AES128_CM_HMAC_SHA1_32(new byte[] {0x00, 0x02}),

    SRTP_NULL_HMAC_SHA1_80(new byte[] {0x00, 0x05}),
    SRTP_NULL_HMAC_SHA1_32(new byte[] {0x00, 0x06}),
    SRTP_AEAD_AES_128_GCM(new byte[] {0x00, 0x07}),
    SRTP_AEAD_AES_256_GCM(new byte[] {0x00, 0x08}),
    DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM(new byte[] {0x00, 0x09}),
    DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM(new byte[] {0x00, 0x0A}),
    SRTP_ARIA_128_CTR_HMAC_SHA1_80(new byte[] {0x00, 0x0B}),
    SRTP_ARIA_128_CTR_HMAC_SHA1_32(new byte[] {0x00, 0x0C}),
    SRTP_ARIA_256_CTR_HMAC_SHA1_80(new byte[] {0x00, 0x0D}),
    SRTP_ARIA_256_CTR_HMAC_SHA1_32(new byte[] {0x00, 0x0E}),
    SRTP_AEAD_ARIA_128_GCM(new byte[] {0x00, 0x0F}),
    SRTP_AEAD_ARIA_256_GCM(new byte[] {0x00, 0x10});

    private final byte[] srtpProtectionProfiles;
    private static final Map<Integer, SrtpProtectionProfile> MAP;

    private static final Logger LOGGER = LogManager.getLogger();

    SrtpProtectionProfile(byte[] value) {
        this.srtpProtectionProfiles = value;
    }

    static {
        MAP = new HashMap<>();
        for (SrtpProtectionProfile c : values()) {
            MAP.put(DataConverter.bytesToInt(c.srtpProtectionProfiles), c);
        }
    }

    public byte[] getByteValue() {
        return srtpProtectionProfiles;
    }

    public static SrtpProtectionProfile getProfileByType(byte[] value) {
        return MAP.get(DataConverter.bytesToInt(value));
    }

    public static List<SrtpProtectionProfile> getProfilesAsArrayList(byte[] value) {
        List<SrtpProtectionProfile> profileList = new ArrayList<>();

        for (int i = 0; i < value.length; i += 2) {
            if (i + 1 < value.length) {
                profileList.add(
                        SrtpProtectionProfile.getProfileByType(
                                new byte[] {value[i], value[i + 1]}));
            } else {
                LOGGER.warn(
                        "value cannot be converted into an SrtpProtectionProfile - not enough bytes left");
            }
        }

        return profileList;
    }
}
