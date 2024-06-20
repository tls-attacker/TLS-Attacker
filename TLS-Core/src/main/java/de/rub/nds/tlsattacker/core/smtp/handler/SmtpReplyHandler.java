package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;

public class SmtpReplyHandler<CommandT extends SmtpReply> extends SmtpMessageHandler<CommandT> {
    public SmtpReplyHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContext(SmtpReply smtpMessage) {
    }
}
