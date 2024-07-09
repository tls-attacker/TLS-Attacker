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
import de.rub.nds.tlsattacker.core.smtp.parser.VRFYCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.EXPNCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.VRFYCommandPreparator;
import java.io.InputStream;

public class SmtpEXPNCommand extends SmtpCommand {

    private static final String COMMAND_NAME = "EXPN";
    private String username;
    private String mailbox;

    public SmtpEXPNCommand() {
        super(COMMAND_NAME, null);
    }

    public String getUsername() {
        return username;
    }

    public String getMailbox() {
        return mailbox;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setMailbox(String mailbox) {
        this.mailbox = mailbox;
    }

    @Override
    public VRFYCommandParser getParser(SmtpContext context, InputStream stream) {
        return new VRFYCommandParser(stream);
    }

    @Override
    public EXPNCommandPreparator getPreparator(SmtpContext context) {
        return new EXPNCommandPreparator(context, this);
    }
}
