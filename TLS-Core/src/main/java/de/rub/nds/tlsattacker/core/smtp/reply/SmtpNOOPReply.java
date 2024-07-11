package de.rub.nds.tlsattacker.core.smtp.reply;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.parser.NOOPReplyParser;
import de.rub.nds.tlsattacker.core.smtp.parser.SmtpMessageParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.NOOPReplyPreparator;
import de.rub.nds.tlsattacker.core.smtp.preparator.SmtpMessagePreparator;

import java.io.InputStream;

public class SmtpNOOPReply extends SmtpReply {
    //TODO: shift this to Config somehow
    private String noopMessage = "OK";

    @Override
    public NOOPReplyParser getParser(SmtpContext context, InputStream stream) {
        return new NOOPReplyParser(stream);
    }

    @Override
    public NOOPReplyPreparator getPreparator(SmtpContext context) {
        return new NOOPReplyPreparator(context, this);
    }

    public String getNoopMessage() {
        return noopMessage;
    }

    public void setNoopMessage(String noopMessage) {
        this.noopMessage = noopMessage;
    }
}
