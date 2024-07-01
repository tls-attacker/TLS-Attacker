package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SmtpCommandPreparator<CommandT extends SmtpCommand> extends SmtpMessagePreparator<CommandT> {

    public SmtpCommandPreparator(Chooser chooser, CommandT command) {
        super(chooser, command);
    }

    @Override
    public void prepare() {}
}
