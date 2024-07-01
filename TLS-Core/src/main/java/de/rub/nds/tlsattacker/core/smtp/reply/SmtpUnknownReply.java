package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;

import java.io.InputStream;

public class SmtpUnknownReply extends SmtpReply {
    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(SmtpContext context, InputStream stream) {
        throw new UnsupportedOperationException("Unknown replies are not supported yet.");
    }
}
