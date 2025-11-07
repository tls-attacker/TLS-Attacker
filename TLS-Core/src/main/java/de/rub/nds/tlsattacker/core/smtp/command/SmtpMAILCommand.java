/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpMAILCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parameters.SmtpParameters;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpMAILCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpMAILCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * This class represents an SMTP MAIL command, which is used to initiate a mail transaction. The
 * argument clause contains a reverse-path and may contain optional parameter. The reverse path
 * represents the senders mailbox. Example: <br>
 *
 * <pre>
 * C: MAIL FROM: &lt;seal@upb.de&gt;
 * S: 250 2.1.0 Ok
 * </pre>
 */
@XmlRootElement
public class SmtpMAILCommand extends SmtpCommand {
    private String reversePath;

    private List<SmtpParameters> MAILparameters;

    public SmtpMAILCommand() {
        super(SmtpCommandType.MAIL);
        this.MAILparameters = new ArrayList<>();
    }

    public SmtpMAILCommand(String reversePath) {
        this();
        this.reversePath = reversePath;
    }

    public SmtpMAILCommand(String reversePath, List<SmtpParameters> parameters) {
        this();
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
    public SmtpMAILCommandParser getParser(Context context, InputStream stream) {
        return new SmtpMAILCommandParser(stream);
    }

    @Override
    public SmtpMAILCommandPreparator getPreparator(Context context) {
        return new SmtpMAILCommandPreparator(context.getSmtpContext(), this);
    }

    @Override
    public SmtpMAILCommandHandler getHandler(Context context) {
        return new SmtpMAILCommandHandler(context.getSmtpContext());
    }

    public List<SmtpParameters> getMAILparameters() {
        return MAILparameters;
    }
}
