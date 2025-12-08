/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.handler;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3InitialGreeting;

public class Pop3InitialGreetingHandler extends Pop3ReplyHandler<Pop3InitialGreeting> {
    public Pop3InitialGreetingHandler(Pop3Context pop3Context) {
        super(pop3Context);
    }

    @Override
    public void adjustContext(Pop3InitialGreeting pop3Message) {
        this.getContext().setGreetingReceived(true);
    }
}
