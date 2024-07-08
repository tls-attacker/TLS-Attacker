package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpHELPCommand;

public class HELPCommandPreparator extends SmtpCommandPreparator<SmtpHELPCommand> {
    public HELPCommandPreparator(SmtpContext context, SmtpHELPCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        this.getCommand().setVerb("HELP");
    }
}
