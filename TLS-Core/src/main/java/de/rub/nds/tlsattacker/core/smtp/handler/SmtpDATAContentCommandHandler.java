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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpDATAContentCommand;

public class SmtpDATAContentCommandHandler extends SmtpCommandHandler<SmtpDATAContentCommand> {
    public SmtpDATAContentCommandHandler(SmtpContext context) {
        super(context);
    }

    /**
     * Saves the data transmitted in the DATA command to the context.
     * @param smtpCommand the command to process
     * @see SmtpContext#mailDataBuffer
     */
    @Override
    public void adjustContextSpecific(SmtpDATAContentCommand smtpCommand) {
        this.getContext().setMailDataBuffer(smtpCommand.getLines());
    }
}
