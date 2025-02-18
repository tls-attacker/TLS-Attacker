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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpQUITCommand;

public class SmtpQUITCommandHandler extends SmtpCommandHandler<SmtpQUITCommand> {
    public SmtpQUITCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    /**
     * Sets the clientRequestedClose flag in the context.
     * @param smtpCommand the command to process
     * @see SmtpContext#clientRequestedClose
     */
    @Override
    public void adjustContextSpecific(SmtpQUITCommand smtpCommand) {
        this.getContext().setClientRequestedClose(true);
    }
}
