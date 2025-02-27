package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;

public class SmtpEHLOReplyHandler extends SmtpReplyHandler<SmtpEHLOReply>  {
    public SmtpEHLOReplyHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContext(SmtpEHLOReply container) {
        this.getContext().setServerIdentity(container.getDomain());
        this.getContext().setNegotiatedExtensions(container.getExtensions());
    }
}
