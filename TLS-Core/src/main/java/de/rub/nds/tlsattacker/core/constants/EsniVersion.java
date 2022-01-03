/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

public enum EsniVersion {
    DRAFT_0(EsniDnsKeyRecordVersion.NULL),
    DRAFT_1(EsniDnsKeyRecordVersion.VERSION_FF01),
    DRAFT_2(EsniDnsKeyRecordVersion.VERSION_FF01),
    DRAFT_3(EsniDnsKeyRecordVersion.VERSION_FF02),
    DRAFT_4(EsniDnsKeyRecordVersion.VERSION_FF03),
    DRAFT_5(EsniDnsKeyRecordVersion.VERSION_FF03);

    EsniVersion(EsniDnsKeyRecordVersion dnsKeyRecordVersion) {
        this.dnsKeyRecordVersion = dnsKeyRecordVersion;
    }

    EsniDnsKeyRecordVersion dnsKeyRecordVersion;

    public EsniDnsKeyRecordVersion getDnsKeyRecordVersion() {
        return this.dnsKeyRecordVersion;
    }
}
