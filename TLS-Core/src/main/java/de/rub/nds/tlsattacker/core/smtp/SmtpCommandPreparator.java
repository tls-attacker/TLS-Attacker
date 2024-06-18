package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SmtpCommandPreparator<CommandT extends SmtpCommand> extends SmtpMessagePreparator<CommandT> {

    private final CommandT command;

    public SmtpCommandPreparator(Chooser chooser, CommandT command) {
        super(chooser, command);
        this.command = command;
    }

    @Override
    public void prepare() {}

    public CommandT getCommand() {
        return command;
    }
}
