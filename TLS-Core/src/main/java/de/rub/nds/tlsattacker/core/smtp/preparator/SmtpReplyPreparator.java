package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SmtpReplyPreparator<ReplyT extends SmtpReply> extends SmtpMessagePreparator<ReplyT> {
    public SmtpReplyPreparator(Chooser chooser, ReplyT reply) {
        super(chooser, reply);
    }

    @Override
    public void prepare() {}
}
