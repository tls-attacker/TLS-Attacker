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
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public abstract class SmtpMessagePreparator<MessageT extends SmtpMessage>
        extends Preparator<MessageT> {

    protected final SmtpContext context;

    public SmtpMessagePreparator(Chooser chooser, MessageT message) {
        super(chooser, message);
        this.context = chooser.getContext().getSmtpContext();
    }

    public SmtpContext getContext() {
        return context;
    }
}
