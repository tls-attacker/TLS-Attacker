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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;

public class VRFYCommandPreparator extends SmtpCommandPreparator<SmtpVRFYCommand> {
    public VRFYCommandPreparator(SmtpContext context, SmtpVRFYCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        this.getObject().setParameters(this.getObject().getUsername());
    }
}
