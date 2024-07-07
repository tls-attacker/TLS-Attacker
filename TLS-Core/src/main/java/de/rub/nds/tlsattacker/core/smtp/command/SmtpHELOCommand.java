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
import de.rub.nds.tlsattacker.core.smtp.handler.HELOCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.HELOCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.HELOCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import org.bouncycastle.util.IPAddress;

/**
 * This class represents an SMTP HELO command, which is used to identify the client to the server.
 * The HELO command is used with a domain, rather than an address literal. Although it is very
 * similar to the EHLO command, it is implemented not as a subclass, because it does carry some
 * implications regarding the client version and how to handle messages.
 */
@XmlRootElement
public class SmtpHELOCommand extends SmtpCommand {
    private String domain;

    public SmtpHELOCommand() {
        super("HELO");
    }

    public SmtpHELOCommand(String domain) {
        super("HELO", domain);
        if (IPAddress.isValid(domain)) {
            // might be superfluous could be removed later
            throw new IllegalArgumentException("HELO cannot be used with an adress literal.");
        } else {
            this.domain = domain;
        }
    }

    @Override
    public HELOCommandParser getParser(SmtpContext context, InputStream stream) {
        return new HELOCommandParser(stream);
    }

    @Override
    public HELOCommandPreparator getPreparator(SmtpContext context) {
        return new HELOCommandPreparator(context, this);
    }

    @Override
    public HELOCommandHandler getHandler(SmtpContext smtpContext) {
        return new HELOCommandHandler(smtpContext);
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }
}
