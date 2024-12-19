/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.handler.EHLOCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.command.EHLOCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.EHLOCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import org.bouncycastle.util.IPAddress;

/**
 * This class represents an SMTP EHLO command, which is used to identify the client to the server.
 * The EHLO command mostly replaces the old HELO command: The difference is that EHLO can be used
 * with an address literal as well as a domain, rather than just a domain. <br>
 * Example:
 *
 * <pre>
 * C: EHLO client.example.com
 * S: 250-smtp.example.com Hello client.example.com
 * S: 250-SIZE 35882577
 * S: 250-PIPELINING
 * S: 250-AUTH PLAIN LOGIN
 * S: 250 8BITMIME
 * </pre>
 */
@XmlRootElement
public class SmtpEHLOCommand extends SmtpCommand {
    private String clientIdentity;
    private boolean hasAddressLiteral = false;

    public SmtpEHLOCommand() {
        super("EHLO");
    }

    public SmtpEHLOCommand(String clientIdentity) {
        super("EHLO", clientIdentity);
        if (IPAddress.isValid(clientIdentity)) {
            this.hasAddressLiteral = true;
        }
        this.clientIdentity = clientIdentity;
    }

    public SmtpEHLOCommand(IPAddress ip) {
        super("EHLO", ip.toString());
        this.clientIdentity = ip.toString();
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }

    public String getClientIdentity() {
        return clientIdentity;
    }

    public void setClientIdentity(String clientIdentity) {
        this.clientIdentity = clientIdentity;
    }

    public boolean hasAddressLiteral() {
        return hasAddressLiteral;
    }

    public void setHasAddressLiteral(boolean hasAddressLiteral) {
        this.hasAddressLiteral = hasAddressLiteral;
    }

    @Override
    public EHLOCommandParser getParser(SmtpContext context, InputStream stream) {
        return new EHLOCommandParser(stream);
    }

    @Override
    public EHLOCommandPreparator getPreparator(SmtpContext context) {
        return new EHLOCommandPreparator(context, this);
    }

    @Override
    public EHLOCommandHandler getHandler(SmtpContext context) {
        return new EHLOCommandHandler(context);
    }
}
