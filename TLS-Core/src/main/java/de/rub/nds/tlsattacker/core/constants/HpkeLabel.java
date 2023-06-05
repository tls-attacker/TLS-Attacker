/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public enum HpkeLabel {
    EMPTY(""),

    PSK_ID_HASH("psk_id_hash"),

    INFO_HASH("info_hash"),

    SECRET("secret"),

    KEY("key"),

    BASE_NONCE("base_nonce"),

    EXPAND("exp"),

    KEM("KEM"),

    HPKE("HPKE"),

    EXTRACT_AND_EXPAND("eae_prk"),

    SHARED_SECRET("shared_secret"),

    HPKE_VERSION_1("HPKE-v1");

    private final String name;

    private HpkeLabel(String name) {
        this.name = name;
    }

    public byte[] getBytes() {
        return this.name.getBytes();
    }
}
