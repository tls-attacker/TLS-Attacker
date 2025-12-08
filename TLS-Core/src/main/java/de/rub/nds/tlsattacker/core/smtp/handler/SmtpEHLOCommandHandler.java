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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;

public class SmtpEHLOCommandHandler extends SmtpCommandHandler<SmtpEHLOCommand> {
    public SmtpEHLOCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    /**
     * Saves the client identity transmitted in the EHLO command to the context. Note that compared
     * to {@link SmtpHELOCommandHandler}, EHLOs are allowed to contain a domain OR address literal.
     *
     * @param smtpCommand the command to process
     * @see SmtpContext#getClientIdentity()
     */
    @Override
    public void adjustContextSpecific(SmtpEHLOCommand smtpCommand) {
        this.getContext().getSmtpContext().setClientIdentity(smtpCommand.getClientIdentity());
    }
}
