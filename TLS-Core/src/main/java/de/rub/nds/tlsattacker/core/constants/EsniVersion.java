/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public enum EsniVersion {
    DRAFT_0(EsniDnsKeyRecordVersion.NULL),
    DRAFT_1(EsniDnsKeyRecordVersion.FF01),
    DRAFT_2(EsniDnsKeyRecordVersion.FF01),
    DRAFT_3(EsniDnsKeyRecordVersion.FF02),
    DRAFT_4(EsniDnsKeyRecordVersion.FF03),
    DRAFT_5(EsniDnsKeyRecordVersion.FF03);

    EsniVersion(EsniDnsKeyRecordVersion dnsKeyRecordVersion) {
        this.dnsKeyRecordVersion = dnsKeyRecordVersion;
    }

    EsniDnsKeyRecordVersion dnsKeyRecordVersion;

    public EsniDnsKeyRecordVersion getDnsKeyRecordVersion() {
        return this.dnsKeyRecordVersion;
    }
}
