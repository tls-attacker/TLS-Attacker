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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpDATAContentCommand;

import java.util.List;

public class DATAContentCommandPreparator extends SmtpCommandPreparator<SmtpDATAContentCommand> {
    public DATAContentCommandPreparator(SmtpContext context, SmtpDATAContentCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        if (this.getObject().getLines() == null) {
            this.getObject().setLines(chooser.getConfig().getDefaultSmtpMessage());
        }
        this.getObject().setParameters(String.join("\r\n", this.getObject().getLines()) + "\r\n.");
    }
}
