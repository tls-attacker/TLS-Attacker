package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpInitialGreeting;

import java.util.List;

public class InitialGreetingPreparator extends SmtpReplyPreparator<SmtpInitialGreeting> {
    public InitialGreetingPreparator(SmtpContext context, SmtpInitialGreeting smtpInitialGreeting) {
        super(context.getChooser(), smtpInitialGreeting);
    }

    @Override
    public void prepare() {
        this.getObject().setReplyCode(this.getObject().getReplyCode());
        this.getObject().setReplyLines(List.of(getObject().getGreeting()));
    }
}
