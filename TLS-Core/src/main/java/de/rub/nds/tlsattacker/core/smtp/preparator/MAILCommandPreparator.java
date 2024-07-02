package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;

public class MAILCommandPreparator extends SmtpCommandPreparator<SmtpMAILCommand> {
    public MAILCommandPreparator(SmtpContext context, SmtpMAILCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        this.getCommand().setVerb("MAIL");
    }
}
