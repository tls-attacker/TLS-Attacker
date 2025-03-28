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
        Pop3Command lastCommand = this.getContext().getLastCommand();

        if (lastCommand instanceof Pop3RETRCommand && pop3RETRReply.statusIsPositive()) {
            this.getContext().addRetrievedMessage(((Pop3RETRCommand) lastCommand).getMessageNumber());
        }
    }
}
