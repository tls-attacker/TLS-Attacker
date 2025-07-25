/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.constants;

public enum StarttlsMessage {
    FTP_S_CONNECTED("211-Extensions supported\r\nAUTH TLS\r\n211 END\r\n"),
    FTP_TLS("AUTH TLS\r\n"),
    FTP_S_READY("234 AUTH command ok. Initializing TLS Connection.\r\n"),
    IMAP_S_CONNECTED(". OK IMAP4rev1 Service Ready\r\n"),
    IMAP_TLS("a STARTTLS\r\n"),
    IMAP_S_READY("a OK BEGIN TLS NEGOTIATION\r\n"),
    POP3_S_CONNECTED("+OK Service Ready\r\n"),
    POP3_TLS("STLS\r\n"),
    POP3_S_READY("+OK Begin TLS negotiation\r\n"),
    SMTP_S_CONNECTED("220 mail.example.com SMTP service ready\r\n"),
    SMTP_C_CONNECTED("EHLO mail.example.org\r\n"),
    SMTP_S_OK("250-mail.example.org offers a warm hug of welcome\r\n"),
    SMTP_TLS("STARTTLS\r\n"),
    SMTP_S_READY("220 GO AHEAD\r\n");

    private final String starttlsMessage;

    StarttlsMessage(String starttlsMessage) {
        this.starttlsMessage = starttlsMessage;
    }

    public String getStarttlsMessage() {
        return starttlsMessage;
    }
}
