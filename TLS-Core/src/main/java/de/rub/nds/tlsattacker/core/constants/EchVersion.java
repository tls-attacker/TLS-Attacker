/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public enum EchVersion {

    // TODO: support draft 6-14
    DRAFT_14(EchConfigVersion.DRAFT_FF0D);

    private EchVersion(EchConfigVersion echConfigVersion) {
        this.echConfigVersion = echConfigVersion;
    }

    final EchConfigVersion echConfigVersion;

    public EchConfigVersion getEchConfigVersion() {
        return this.echConfigVersion;
    }
}
