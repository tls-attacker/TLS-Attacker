/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.constants;

public enum StarttlsType {
    NONE(""),
    FTP("234"),
    IMAP("negotiation"),
    POP3("+OK"),
    SMTP("220");

    /**
     * This string is used to identify if the server accepted a STARTTLS command. If it is present in the response we
     * believe that the server supports starttls.
     */
    private String negotiatationString;

    private StarttlsType(String negotiatationString) {
        this.negotiatationString = negotiatationString;
    }

    public String getNegotiatationString() {
        return negotiatationString;
    }

}
