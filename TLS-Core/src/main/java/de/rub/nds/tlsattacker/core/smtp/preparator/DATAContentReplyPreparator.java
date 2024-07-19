package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpDATAContentReply;

public class DATAContentReplyPreparator extends SmtpReplyPreparator<SmtpDATAContentReply> {
    public DATAContentReplyPreparator(SmtpContext context, SmtpDATAContentReply reply) {
        super(context.getChooser(), reply);
    }

    @Override
    public void prepare() {
        this.getObject().setReplyLines(this.getObject().getLineContents());
    }
}
