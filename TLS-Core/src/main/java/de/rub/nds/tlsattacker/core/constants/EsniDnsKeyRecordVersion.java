/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public enum EsniDnsKeyRecordVersion {
    NULL(null),
    VERSION_FF01(new byte[] { (byte) 0xff, (byte) 0x01 }),
    VERSION_FF02(new byte[] { (byte) 0xff, (byte) 0x02 }),
    VERSION_FF03(new byte[] { (byte) 0xff, (byte) 0x03 });

    EsniDnsKeyRecordVersion(byte[] byteValue) {
        this.byteValue = byteValue;
    }

    private static final Map<BigInteger, EsniDnsKeyRecordVersion> MAP;
    private final byte[] byteValue;

    public byte[] getByteValue() {
        return this.byteValue;
    }

    static {
        MAP = new HashMap<>();
        for (EsniDnsKeyRecordVersion version : EsniDnsKeyRecordVersion.values()) {
            byte[] versionBytes = version.getByteValue();
            if (versionBytes != null) {
                BigInteger hashMapKey = new BigInteger(versionBytes);
                MAP.put(hashMapKey, version);
            }
        }
    }

    public static EsniDnsKeyRecordVersion getEnumByByte(byte[] versionBytes) {
        if (versionBytes == null) {
            return EsniDnsKeyRecordVersion.NULL;
        } else {
            BigInteger hashMapKey = new BigInteger(versionBytes);
            return MAP.get(hashMapKey);
        }
    }

}
