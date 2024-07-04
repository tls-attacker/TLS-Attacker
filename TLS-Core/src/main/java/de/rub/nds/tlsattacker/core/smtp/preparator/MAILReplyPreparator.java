package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpMAILReply;

import java.util.ArrayList;
import java.util.List;

public class MAILReplyPreparator extends SmtpReplyPreparator<SmtpMAILReply> {
    public MAILReplyPreparator(SmtpContext context, SmtpMAILReply reply) {
        super(context.getChooser(), reply);
    }

    @Override
    public void prepare() {
        this.getObject().setReplyCode(this.getObject().getReplyCode());
        List<String> replyLines = new ArrayList<>();
        String message = getObject().getMessage();
        replyLines.add(message);
        this.getObject().setReplyLines(replyLines);
    }
}
