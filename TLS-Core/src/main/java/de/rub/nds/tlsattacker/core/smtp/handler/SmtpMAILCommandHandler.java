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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;

public class SmtpMAILCommandHandler extends SmtpCommandHandler<SmtpMAILCommand> {
    public SmtpMAILCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    /**
     * Saves the reverse path (i.e. sender address) transmitted in the MAIL command to the context.
     *
     * @param smtpCommand the command to process
     * @see SmtpContext#getReversePathBuffer()
     */
    @Override
    public void adjustContextSpecific(SmtpMAILCommand smtpCommand) {
        this.getContext().getSmtpContext().clearBuffers();
        this.getContext().getSmtpContext().insertReversePath(smtpCommand.getReversePath());
    }
}
