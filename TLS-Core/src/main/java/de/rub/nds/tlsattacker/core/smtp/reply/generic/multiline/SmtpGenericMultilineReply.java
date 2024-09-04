package de.rub.nds.tlsattacker.core.smtp.reply.generic.multiline;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.reply.SmtpGenericReplyParser;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;

import java.io.InputStream;
import java.util.List;

public class SmtpGenericMultilineReply extends SmtpReply {

    List<String> humanReadableMessages;

    public List<String> getHumanReadableMessages() {
        return humanReadableMessages;
    }

    public void setHumanReadableMessages(List<String> humanReadableMessages) {
        this.humanReadableMessages = humanReadableMessages;
    }

    public void addHumanReadableMessages(String humanReadableMessage) {
        this.humanReadableMessages.add(humanReadableMessage);
    }

    @Override
    public SmtpGenericReplyParser<SmtpGenericMultilineReply> getParser(SmtpContext context, InputStream stream) {
        return new SmtpGenericReplyParser<>(stream);
    }

    @Override
    public String toString() {
        char SP = ' ';
        char DASH = '-';
        char CR = '\r';
        char LF = '\n';

        StringBuilder sb = new StringBuilder();
        String replyCodeString =  this.replyCode != null ? String.valueOf(this.replyCode) : "";
        String replyCodePrefix = this.replyCode != null ? replyCodeString + DASH : "";

        for (int i = 0; i < this.humanReadableMessages.size() - 1; i++) {
            sb.append(replyCodePrefix);
            sb.append(this.humanReadableMessages.get(i));
            sb.append(LF);
        }

        sb.append(replyCodeString);
        sb.append(SP);
        sb.append(this.humanReadableMessages.get(this.humanReadableMessages.size() - 1));
        sb.append(CR);
        sb.append(LF);

        return sb.toString();
    }
}
