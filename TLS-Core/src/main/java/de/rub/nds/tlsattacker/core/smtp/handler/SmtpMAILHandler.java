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

public class SmtpMAILHandler extends SmtpCommandHandler<SmtpMAILCommand> {
    public SmtpMAILHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContextSpecific(SmtpMAILCommand smtpCommand) {
        this.getContext().setReversePathBuffer(smtpCommand.getReversePathBuffer());
        this.getContext().setForwardPathBuffer(smtpCommand.getForwardPathBuffer());
        this.getContext().setMailDataBuffer(smtpCommand.getMailDataBuffer());
    }
}
