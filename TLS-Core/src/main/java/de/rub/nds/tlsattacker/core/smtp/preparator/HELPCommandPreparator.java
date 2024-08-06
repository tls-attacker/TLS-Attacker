package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpHELPCommand;
import de.rub.nds.tlsattacker.core.smtp.parameters.SmtpParameters;

import java.util.ArrayList;
import java.util.List;

public class HELPCommandPreparator extends SmtpCommandPreparator<SmtpHELPCommand> {
    public HELPCommandPreparator(SmtpContext context, SmtpHELPCommand command) {
        super(context.getChooser(), command);
    }

    /**
     * Prepares a HELP command by setting verb.
     */
    @Override
    public void prepare() {
        this.getObject().setVerb("HELP");
    }
}
