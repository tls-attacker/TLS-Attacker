/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import org.bouncycastle.util.IPAddress;

/**
 * This class represents an SMTP EHLO command, which is used to identify the client to the server.
 * The EHLO command mostly replaces the old HELO command: The difference is that EHLO can be used
 * with an address literal as well as a domain, rather than just a domain.
 */
public class SmtpEHLOCommand extends SmtpCommand {
    // TODO: Maybe subclass this to accommodate HELO command as well

    private String domain;
    private boolean hasAddressLiteral = false;

    public SmtpEHLOCommand() {
        super("EHLO", null);
    }

    public SmtpEHLOCommand(String domain) {
        super("EHLO", domain);
    }

    public SmtpEHLOCommand(IPAddress ip) {
        super("EHLO", ip.toString());
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public boolean hasAddressLiteral() {
        return hasAddressLiteral;
    }

    public void setHasAddressLiteral(boolean hasAddressLiteral) {
        this.hasAddressLiteral = hasAddressLiteral;
    }
}
