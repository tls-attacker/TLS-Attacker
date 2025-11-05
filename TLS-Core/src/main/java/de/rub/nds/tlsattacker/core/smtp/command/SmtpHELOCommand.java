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
import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpHELOCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpHELOCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpHELOCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This class represents an SMTP HELO command, which is used to identify the client to the server.
 * The HELO command is used with a domain, rather than an address literal. Although it is very
 * similar to the EHLO command, it is implemented not as a subclass, because it does carry some
 * implications regarding the client version and how to handle messages. <br>
 * SMTP HELO does not have its own reply, because the HELO Reply is a special case of the EHLO
 * reply. Example:
 *
 * <pre>
 * C: EHLO upb.de
 * S: 250-upb.de Hello
 * S: 250-SIZE 35882577
 * S: 250-PIPELINING
 * S: 250-AUTH PLAIN LOGIN
 * S: 250 8BITMIME
 * </pre>
 *
 * @see SmtpEHLOCommand
 * @see SmtpEHLOReply
 */
@XmlRootElement
public class SmtpHELOCommand extends SmtpCommand {
    private String domain;

    public SmtpHELOCommand() {
        super(SmtpCommandType.HELO);
    }

    public SmtpHELOCommand(String domain) {
        this();
        this.domain = domain;
    }

    @Override
    public SmtpHELOCommandParser getParser(SmtpContext context, InputStream stream) {
        return new SmtpHELOCommandParser(stream);
    }

    @Override
    public SmtpHELOCommandPreparator getPreparator(SmtpContext context) {
        return new SmtpHELOCommandPreparator(context, this);
    }

    @Override
    public SmtpHELOCommandHandler getHandler(SmtpContext smtpContext) {
        return new SmtpHELOCommandHandler(smtpContext);
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }
}
