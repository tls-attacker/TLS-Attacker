/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;

public class SmtpCommandHandler<CommandT extends SmtpCommand> extends SmtpMessageHandler<CommandT> {

    public SmtpCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContext(CommandT smtpCommand) {
        this.context.setLastCommand(smtpCommand);
        adjustContextSpecific(smtpCommand);
    }

    public void adjustContextSpecific(CommandT smtpCommand) {
        // empty, override if needed
    }
}
