package de.rub.nds.tlsattacker.core.pop3.reply;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.parser.reply.RSETReplyParser;

import java.io.InputStream;

public class Pop3RSETReply extends Pop3Reply{

    public Pop3RSETReply() {super();}

    @Override
    public RSETReplyParser getParser(Pop3Context context, InputStream stream) {
        return new RSETReplyParser(stream);
    }
}
