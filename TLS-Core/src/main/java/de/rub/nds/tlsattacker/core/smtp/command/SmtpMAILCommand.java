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
import de.rub.nds.tlsattacker.core.smtp.handler.MAILCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parameters.SmtpParameters;
import de.rub.nds.tlsattacker.core.smtp.parser.MAILCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.MAILCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * This class represents an SMTP MAIL command, which is used to initiate a mail transaction. The
 * argument clause contains a reverse-path and may contain optional parameter. The reverse path
 * represents the senders mailbox.
 */
@XmlRootElement
public class SmtpMAILCommand extends SmtpCommand {

    private static final String COMMAND = "MAIL";

    private String reversePath;

    private List<SmtpParameters> MAILparameters;

    public SmtpMAILCommand() {
        super(COMMAND, null);
        this.MAILparameters = new ArrayList<>();
    }

    public SmtpMAILCommand(String reversePath) {
        super(COMMAND, reversePath);
        this.MAILparameters = new ArrayList<>();
    }

    public SmtpMAILCommand(String reversePath, List<SmtpParameters> parameters) {
        super(COMMAND, reversePath);
        this.reversePath = reversePath;
        this.MAILparameters = parameters;
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

    @Override
    public MAILCommandParser getParser(SmtpContext context, InputStream stream) {
        return new MAILCommandParser(stream);
    }

    @Override
    public MAILCommandPreparator getPreparator(SmtpContext context) {
        return new MAILCommandPreparator(context, this);
    }

    @Override
    public MAILCommandHandler getHandler(SmtpContext context) {
        return new MAILCommandHandler(context);
    }

    public List<SmtpParameters> getMAILparameters() {
        return MAILparameters;
    }
}
