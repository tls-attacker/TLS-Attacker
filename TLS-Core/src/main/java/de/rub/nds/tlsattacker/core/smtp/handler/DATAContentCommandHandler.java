package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpDATAContentCommand;

public class DATAContentCommandHandler extends SmtpCommandHandler<SmtpDATAContentCommand> {
    public DATAContentCommandHandler(SmtpContext context) {
        super(context);
    }

    @Override
    public void adjustContextSpecific(SmtpDATAContentCommand smtpCommand) {
        this.getContext().setMailDataBuffer(smtpCommand.getLines());
    }
}
