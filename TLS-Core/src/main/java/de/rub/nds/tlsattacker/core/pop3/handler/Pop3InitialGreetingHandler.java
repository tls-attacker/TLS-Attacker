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
