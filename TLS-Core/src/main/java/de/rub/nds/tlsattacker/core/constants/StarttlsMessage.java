/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.constants;

public enum StarttlsMessage {
    FTP_S_CONNECTED("220\r\n"),
    FTP_TLS("AUTH TLS\r\n"),
    FTP_S_READY("234\r\n"),
    IMAP_S_CONNECTED(". OK IMAP4rev1 Service Ready\r\n"),
    IMAP_C_CAP(". CAPABILITY\r\n"),
    IMAP_S_CAP(". CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n"),
    IMAP_TLS(". STARTTLS\r\n"),
    IMAP_S_READY(". OK BEGIN TLS NEGOTIATION\r\n"),
    POP3_S_CONNECTED("SERVICE READY\r\n"),
    POP3_TLS("STLS\r\n"),
    POP3_S_READY("+OK Begin TLS negotiation\r\n"),
    SMTP_S_CONNECTED("SERVICE READY\r\n"),
    SMTP_C_CONNECTED("EHLO mail.example.com\r\n"),
    SMTP_TLS("STARTTLS\r\n"),
    SMTP_S_READY("220 GO AHEAD");

    private final String starttlsMessage;

    private StarttlsMessage(String starttlsMessage) {
        this.starttlsMessage = starttlsMessage;
    }

    public String getStarttlsMessage() {
        return starttlsMessage;
    }
}
