package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;

public class SmtpCommandHandler<CommandT extends SmtpCommand> extends SmtpMessageHandler<CommandT> {

    public SmtpCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContext(SmtpCommand smtpCommand) {
        this.context.setLastCommand(smtpCommand);
        adjustContextSpecific(smtpCommand);
    }

    public void adjustContextSpecific(SmtpCommand smtpCommand) {
        // empty, override if needed
    }


}
