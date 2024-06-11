package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;

import java.io.InputStream;

public class SmtpReply extends SmtpMessage {


    @Override
    public SmtpMessageHandler<? extends SmtpMessage> getHandler(SmtpContext smtpContext) {
        return null;
    }

    @Override
    public SmtpMessageParser<? extends SmtpMessage> getParser(SmtpContext context, InputStream stream) {
        return null;
    }

    @Override
    public SmtpMessagePreparator<? extends SmtpMessage> getPreparator(SmtpContext context) {
        return null;
    }

    @Override
    public SmtpMessageSerializer<? extends SmtpMessage> getSerializer(SmtpContext context) {
        return null;
    }

    @Override
    public String toShortString() {
        return "";
    }
}
