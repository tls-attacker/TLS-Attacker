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
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpInitialGreeting;

public class InitialGreetingHandler extends SmtpReplyHandler<SmtpInitialGreeting> {
    public InitialGreetingHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContext(SmtpInitialGreeting smtpMessage) {
        this.getContext().setGreetingReceived(true);
    }
}
