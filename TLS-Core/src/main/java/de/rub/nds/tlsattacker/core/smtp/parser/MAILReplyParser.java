package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpMAILReply;

import java.io.InputStream;

public class MAILReplyParser extends SmtpReplyParser<SmtpMAILReply> {

    public MAILReplyParser(InputStream stream) {
        super(stream);
    }
}
