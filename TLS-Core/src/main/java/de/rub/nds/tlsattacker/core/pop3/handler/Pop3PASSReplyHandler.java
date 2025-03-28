package de.rub.nds.tlsattacker.core.pop3.handler;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3PASSCommand;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3PASSReply;

public class Pop3PASSReplyHandler extends Pop3ReplyHandler<Pop3PASSReply> {
    public Pop3PASSReplyHandler(Pop3Context pop3Context) {
        super(pop3Context);
    }

    @Override
    public void adjustContext(Pop3PASSReply pop3PASSReply) {
        Pop3Command lastCommand = this.getContext().getLastCommand();

        if (lastCommand instanceof Pop3PASSCommand && pop3PASSReply.statusIsPositive()) {
            this.getContext().setClientIsAuthenticated(true);
        }
    }
}
