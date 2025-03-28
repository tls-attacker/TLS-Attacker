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
import de.rub.nds.tlsattacker.core.pop3.command.Pop3DELECommand;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3DELEReply;

public class Pop3DELEReplyHandler extends Pop3ReplyHandler<Pop3DELEReply> {
    public Pop3DELEReplyHandler(Pop3Context pop3Context) {
        super(pop3Context);
    }

    @Override
    public void adjustContext(Pop3DELEReply pop3DELEReply) {
        Pop3Command lastCommand = this.getContext().getLastCommand();

        if (lastCommand instanceof Pop3DELECommand && pop3DELEReply.statusIsPositive()) {
            this.getContext()
                    .addMessageMarkedForDeletion(
                            ((Pop3DELECommand) lastCommand).getMessageNumber());
        }
    }
}
