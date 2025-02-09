package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpReplyParser;

import java.io.InputStream;

public class SmtpUnparseableTestReply extends SmtpReply {
    @Override
    public SmtpReplyParser<? extends SmtpReply> getParser(SmtpContext context, InputStream stream) {
        return new SmtpReplyParser<SmtpUnparseableTestReply>(stream) {
            @Override
            public void parse(SmtpUnparseableTestReply message) {
                try {
                    this.getStream().readAllBytes();
                } catch (Exception e) {
                    throw new ParserException("SmtpUnparseableTestReply emptied stream and was not parsed properly", e);
                }
            }
        };
    }
}
