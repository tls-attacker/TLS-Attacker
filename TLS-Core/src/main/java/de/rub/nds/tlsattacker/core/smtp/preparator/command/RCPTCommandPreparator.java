/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpRCPTCommand;

public class RCPTCommandPreparator extends SmtpCommandPreparator<SmtpRCPTCommand> {
    public RCPTCommandPreparator(SmtpContext context, SmtpRCPTCommand command) {
        super(context.getChooser(), command);
    }

    /**
     * Prepares a RCPT command by setting verb and parameters.
     */
    @Override
    public void prepare() {
        this.getObject().setVerb("RCPT");
        if (this.getObject().getRecipient() == null) {
            this.getObject().setRecipient(chooser.getConfig().getDefaultSmtpForwardPath());
        }
        this.getObject().setParameters("TO:<" + this.getObject().getRecipient() + ">");
    }
}
