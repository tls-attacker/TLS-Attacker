package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;

import java.io.InputStream;

public abstract class SmtpReplyParser<ReplyT extends SmtpReply> extends SmtpMessageParser<ReplyT> {
    public SmtpReplyParser(InputStream stream) {
        super(stream);
    }
}
