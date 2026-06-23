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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpHELOCommand;

public class SmtpHELOCommandHandler extends SmtpCommandHandler<SmtpHELOCommand> {
    public SmtpHELOCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    /**
     * Saves the domain transmitted in the HELO command to the context. Note that compared to {@link
     * SmtpEHLOCommandHandler}, HELOs are not allowed to contain an address literal.
     *
     * @param smtpCommand the command to process
     * @see SmtpContext#getClientIdentity()
     */
    @Override
    public void adjustContextSpecific(SmtpHELOCommand smtpCommand) {
        this.getContext().getSmtpContext().setClientIdentity(smtpCommand.getDomain());
        this.getContext().getSmtpContext().setClientUsedHELO(true);
    }
}
