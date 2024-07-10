package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpDATAContentReply;

public class DATAContentReplyHandler extends SmtpReplyHandler<SmtpDATAContentReply> {
    public DATAContentReplyHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContext(SmtpDATAContentReply container) {
        this.getContext().clearBuffers();
    }
}
