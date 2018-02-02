/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum StarttlsResponse {
    IMAP_ACAP_OK("OK - begin TLS negotiation"),
    IMAP_ACAP_BAD("BAD - command unknown or arguments invalid"),
    POP3_OK("+OK Begin TLS negotiation"),
    POP3_BAD("-ERR");

    private final String response;

    private StarttlsResponse(String response) {
        this.response = response;
    }

    public String getResponse() {
        return response;
    }

}
