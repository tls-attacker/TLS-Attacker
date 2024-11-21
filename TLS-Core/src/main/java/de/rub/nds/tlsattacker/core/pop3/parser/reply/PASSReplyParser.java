package de.rub.nds.tlsattacker.core.pop3.parser.reply;

import de.rub.nds.tlsattacker.core.pop3.reply.Pop3PASSReply;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;

import java.io.InputStream;

public class PASSReplyParser extends Pop3GenericReplyParser<Pop3PASSReply> {
    public PASSReplyParser(InputStream stream) {
        super(stream);
    }
}
