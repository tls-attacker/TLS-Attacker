package de.rub.nds.tlsattacker.core.pop3.handler;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;

public abstract class Pop3MessageHandler<MessageT extends Pop3Message> extends Handler<MessageT> {

    protected final Pop3Context context;

    public Pop3MessageHandler(Pop3Context context) {
        this.context = context;
    }

    public void adjustContext(MessageT container) {}

    public Pop3Context getContext() {
        return context;
    }
}
