package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3NOOPReply;

import java.io.InputStream;

public class NOOPReplyParser extends Pop3GenericReplyParser<Pop3NOOPReply> {
    public NOOPReplyParser(InputStream stream) {
        super(stream);
    }
}
