package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpEHLOReply;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;

public class EHLOReplyHandler extends SmtpReplyHandler<SmtpEHLOReply> {
    public EHLOReplyHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContext(SmtpEHLOReply smtpMessage) {
        if(smtpMessage.getReplyCode() == 502) {
            this.getContext().setServerOnlySupportsEHLO(true);
        }
    }

}
