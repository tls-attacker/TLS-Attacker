package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.Pop3ReplyParser;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.QUITReplyParser;

import java.io.InputStream;

public class Pop3QUITReply extends Pop3Reply {

    public Pop3QUITReply() {super();}

    @Override
    public QUITReplyParser getParser(Pop3Context context, InputStream stream) {
        return new QUITReplyParser(stream);
    }
}
