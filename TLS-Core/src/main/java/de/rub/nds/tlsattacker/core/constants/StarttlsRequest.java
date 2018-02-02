/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum StarttlsRequest {
    STARTTLS("STARTTLS"),
    STLS("STLS");

    private final String command;

    private StarttlsRequest(String command) {
        this.command = command;
    }

    public String getCommand() {
        return command;
    }
}
