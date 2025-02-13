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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpRCPTCommand;
import java.util.List;

public class SmtpRCPTCommandHandler extends SmtpCommandHandler<SmtpRCPTCommand> {
    public SmtpRCPTCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    /**
     * Save recipientBuffer from an RCPT message in context.
     *
     * @param smtpRCPTCommand The message containing the recipient
     */
    @Override
    public void adjustContextSpecific(SmtpRCPTCommand smtpRCPTCommand) {
        this.getContext().setForwardPathBuffer(smtpRCPTCommand.getRecipient());
        List<String> recipients = this.getContext().getRecipientBuffer();
        recipients.add(this.getContext().getForwardPathBuffer());
    }
}
