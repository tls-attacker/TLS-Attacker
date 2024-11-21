package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3DELReply;

import java.io.InputStream;

public class DELReplyParser extends Pop3GenericReplyParser<Pop3DELReply>{
    public DELReplyParser(InputStream stream) {
        super(stream);
    }
}
