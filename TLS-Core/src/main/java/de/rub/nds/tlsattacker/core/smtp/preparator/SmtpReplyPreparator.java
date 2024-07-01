package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SmtpReplyPreparator<ReplyT extends SmtpReply> extends SmtpMessagePreparator<ReplyT> {
    private final ReplyT reply;

    public SmtpReplyPreparator(Chooser chooser, ReplyT reply) {
        super(chooser, reply);
        this.reply = reply;
    }

    @Override
    public void prepare() {}

    public ReplyT getReply() {
        return reply;
    }
}
