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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;
import de.rub.nds.tlsattacker.core.smtp.parameters.SmtpParameters;

public class SmtpMAILCommandPreparator extends SmtpCommandPreparator<SmtpMAILCommand> {
    public SmtpMAILCommandPreparator(SmtpContext context, SmtpMAILCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        if (this.getObject().getReversePath() == null) {
            this.getObject().setReversePath(chooser.getConfig().getDefaultSmtpReversePath());
        }
        StringBuilder pars = new StringBuilder("FROM:<" + this.getObject().getReversePath() + ">");
        //TODO: This would love modern Java Streams
        if (this.getObject().getMAILparameters() != null) {
            for (SmtpParameters MAILparameters : this.getObject().getMAILparameters()) {
                pars.append(" ").append(MAILparameters.serialize());
            }
        }
        this.getObject().setParameters(pars.toString());
    }
}
