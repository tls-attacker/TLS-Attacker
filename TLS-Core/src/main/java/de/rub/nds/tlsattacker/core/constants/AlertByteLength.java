/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

public class AlertByteLength {

    /**
     * certificate length field
     */
    public static final int LEVEL_LENGTH = 1;

    /**
     * version field length
     */
    public static final int DESCRIPTION_LENGTH = 1;

    private AlertByteLength() {
    }
}
