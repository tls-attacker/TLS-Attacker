package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpDATAReply;

public class DATAReplyPreparator extends SmtpReplyPreparator<SmtpDATAReply> {
    public DATAReplyPreparator(SmtpContext context, SmtpDATAReply reply) {
        super(context.getChooser(), reply);
    }

    @Override
    public void prepare() {
        this.getObject().setReplyLines(this.getObject().getLineContents());
    }
}
