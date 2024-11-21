package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3RSETReply;

import java.io.InputStream;

public class RSETReplyParser extends Pop3GenericReplyParser<Pop3RSETReply> {
    public RSETReplyParser(InputStream stream) {
        super(stream);
    }
}
