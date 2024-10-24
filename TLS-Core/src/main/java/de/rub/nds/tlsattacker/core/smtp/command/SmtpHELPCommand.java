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
import de.rub.nds.tlsattacker.core.smtp.parser.command.HELPCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.HELPCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This command causes the server to send helpful information to the client. The command MAY take an
 * argument (e.g., any command name) and return more specific information as a response. Example:
 * <br>
 * C: HELP <br>
 * S: 214-Commands supported: <br>
 * S: 214 HELO EHLO MAIL RCPT DATA RSET VRFY EXPN HELP QUIT AUTH
 */
@XmlRootElement
public class SmtpHELPCommand extends SmtpCommand {
    private static final String COMMAND = "HELP";
    private String subject;

    public SmtpHELPCommand() {
        super(COMMAND);
    }

    public SmtpHELPCommand(String subject) {
        super(COMMAND, subject);
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    @Override
    public HELPCommandParser getParser(SmtpContext context, InputStream stream) {
        return new HELPCommandParser(stream);
    }

    @Override
    public HELPCommandPreparator getPreparator(SmtpContext context) {
        return new HELPCommandPreparator(context, this);
    }
}
