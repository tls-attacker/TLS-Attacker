package de.rub.nds.tlsattacker.core.smtp.reply.generic.singleline;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;

import java.io.InputStream;

public class SmtpGenericSingleLineReply extends SmtpReply {
    String humanReadableMessage;

    public void setHumanReadableMessage(String humanReadableMessage) {
        this.humanReadableMessage = humanReadableMessage;
    }

    public String getHumanReadableMessage() {
        return humanReadableMessage;
    }

    @Override
    public SmtpGenericReplyParser<SmtpGenericSingleLineReply> getParser(SmtpContext context, InputStream stream) {
        return new SmtpGenericReplyParser<>(stream);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        if (this.replyCode != null) {
            sb.append(this.replyCode);
            sb.append(" ");
        }

        if (this.humanReadableMessage != null) {
            sb.append(humanReadableMessage);
        }

        return sb.toString();
    }
}
