package de.rub.nds.tlsattacker.core.pop3.handler;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.reply.Pop3Reply;

public class Pop3ReplyHandler<ReplyT extends Pop3Reply> extends Pop3MessageHandler<ReplyT> {

    public Pop3ReplyHandler(Pop3Context context) {
        super(context);
    }

    @Override
    public void adjustContext(Pop3Reply reply) {}
}
