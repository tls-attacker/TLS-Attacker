/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;
import de.rub.nds.tlsattacker.core.smtp.parameters.SmtpParameters;

public class MAILCommandPreparator extends SmtpCommandPreparator<SmtpMAILCommand> {
    public MAILCommandPreparator(SmtpContext context, SmtpMAILCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        this.getObject().setVerb("MAIL");
        StringBuilder pars = new StringBuilder(this.getObject().getParameters());
        if (this.getObject().getMAILparameters() != null) {
            for (SmtpParameters MAILparameters : this.getObject().getMAILparameters()) {
                pars.append(" ").append(MAILparameters.toString());
            }
        }
        this.getObject().setParameters(pars.toString());
    }
}
