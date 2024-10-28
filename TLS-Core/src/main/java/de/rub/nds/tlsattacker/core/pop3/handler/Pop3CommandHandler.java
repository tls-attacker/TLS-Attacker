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
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;

public class Pop3CommandHandler<CommandT extends Pop3Command> extends Pop3MessageHandler<CommandT> {

    public Pop3CommandHandler(Pop3Context context) {
        super(context);
    }

    @Override
    public void adjustContext(CommandT pop3Command) {
        this.context.setLastCommand(pop3Command);
        adjustContextSpecific(pop3Command);
    }

    public void adjustContextSpecific(CommandT pop3Command) {}
}
