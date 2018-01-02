/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    private SrtpProtectionProfiles(byte[] value) {
        this.srtpProtectionProfiles = value;
    }

    static {
        MAP = new HashMap<>();
        for (SrtpProtectionProfiles c : SrtpProtectionProfiles.values()) {
            MAP.put(valueToInt(c.srtpProtectionProfiles), c);
        }
    }

    public byte[] getByteValue() {
        return srtpProtectionProfiles;
    }

    public static SrtpProtectionProfiles getProfileByType(byte[] value) {
        return MAP.get(valueToInt(value));
    }

    public static List<SrtpProtectionProfiles> getProfilesAsArrayList(byte[] value) {
        List<SrtpProtectionProfiles> profileList = new ArrayList<>();

        for (int i = 0; i < value.length; i += 2) {
            if (value.length > i) {
                profileList.add(SrtpProtectionProfiles.getProfileByType(new byte[] { value[i], value[i + 1] }));
            }
        }

        return profileList;
    }

    private static int valueToInt(byte[] value) {
        if (value.length != 2) {
            // TODO warn
            return 0;
        }
        return (value[0] & 0xff) << 8 | (value[1] & 0xff);
    }

    public byte getMinor() {
        return srtpProtectionProfiles[0];
    }

    public byte getMajor() {
        return srtpProtectionProfiles[1];
    }
}
