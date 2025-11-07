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
import de.rub.nds.tlsattacker.core.pop3.command.Pop3RETRCommand;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3RETRReply;

public class Pop3RETRReplyHandler extends Pop3ReplyHandler<Pop3RETRReply> {
    public Pop3RETRReplyHandler(Pop3Context pop3Context) {
        super(pop3Context);
    }

    @Override
    public void adjustContext(Pop3RETRReply pop3RETRReply) {
        // We need to access the message number from the command that prompted this reply.
        Pop3Command lastCommand = this.getContext().getLastCommand();

        if (lastCommand instanceof Pop3RETRCommand && pop3RETRReply.statusIsPositive()) {
            this.getContext()
                    .addRetrievedMessage(((Pop3RETRCommand) lastCommand).getMessageNumber());
        }
    }
}
