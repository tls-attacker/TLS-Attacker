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
import de.rub.nds.tlsattacker.core.smtp.parser.MAILCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.MAILCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This class represents an SMTP MAIL command, which is used to initiate a mail transaction. The
 * argument clause contains a reverse-path and may contain optional parameter. The reverse path
 * represents the senders mailbox.
 */
@XmlRootElement
public class SmtpMAILCommand extends SmtpCommand {

    private static final String COMMAND = "MAIL";

    private String reversePath;

    private String MailParameters;

    public SmtpMAILCommand() {
        super(COMMAND, null);
    }

    public SmtpMAILCommand(String parameters) {
        super(COMMAND, parameters);
        String[] pars = parameters.split(" ");
        this.reversePath = pars[0];
        if (pars.length > 1) {
            this.MailParameters = pars[1];
        }
    }

    @Override
    public String toCompactString() {
        return super.toCompactString();
    }

    public String getReversePath() {
        return reversePath;
    }

    public void setReversePath(String reversePath) {
        this.reversePath = reversePath;
    }

    public String getMailParameters() {
        return MailParameters;
    }

    public void setMailParameters(String mailParameters) {
        MailParameters = mailParameters;
    }

    @Override
    public MAILCommandParser getParser(SmtpContext context, InputStream stream) {
        return new MAILCommandParser(stream);
    }

    @Override
    public MAILCommandPreparator getPreparator(SmtpContext context) {
        return new MAILCommandPreparator(context, this);
    }
}
