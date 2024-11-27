package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3QUITReply;

import java.io.InputStream;

public class QUITReplyParser extends Pop3GenericReplyParser<Pop3QUITReply> {

    public QUITReplyParser(InputStream stream) {
        super(stream);
    }
}
