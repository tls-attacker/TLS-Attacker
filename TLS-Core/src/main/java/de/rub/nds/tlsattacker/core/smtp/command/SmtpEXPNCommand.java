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
import de.rub.nds.tlsattacker.core.smtp.parser.command.EXPNCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.EXPNCommandPreparator;
import java.io.InputStream;

public class SmtpEXPNCommand extends SmtpCommand {

    private static final String COMMAND_NAME = "EXPN";
    private String mailingList;

    public SmtpEXPNCommand() {
        super(COMMAND_NAME, null);
    }

    public SmtpEXPNCommand(String mailingList) {
        super(COMMAND_NAME, mailingList);
        this.mailingList = mailingList;
    }

    public String getMailingList() {
        return mailingList;
    }

    public void setMailingList(String mailingList) {
        this.mailingList = mailingList;
    }

    @Override
    public EXPNCommandParser getParser(SmtpContext context, InputStream stream) {
        return new EXPNCommandParser(stream);
    }

    @Override
    public EXPNCommandPreparator getPreparator(SmtpContext context) {
        return new EXPNCommandPreparator(context, this);
    }
}
