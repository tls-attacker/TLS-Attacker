/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.reply;

/**
 * Inital Greeting of the POP3 Server when a connection is established Its only use is to be able to
 * distinguish between the initial greeting and truly unknown commands when `receiving` in
 * Pop3Layer. It should never be included in a Workflow.
 */
public class Pop3InitialGreeting extends Pop3Reply {

    public Pop3InitialGreeting() {
        super();
    }

    @Override
    public String toShortString() {
        return "POP3 Initial Greeting";
    }
}
