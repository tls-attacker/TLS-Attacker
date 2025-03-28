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
            this.getContext().addMessageMarkedForDeletion(((Pop3DELECommand) lastCommand).getMessageNumber());
        }
    }
}