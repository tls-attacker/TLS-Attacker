package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;

public class SmtpMAILHandler extends SmtpCommandHandler<SmtpMAILCommand> {
    public SmtpMAILHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContextSpecific(SmtpCommand smtpCommand) {
        this.getContext().setReversePathBuffer(smtpCommand.getReversePathBuffer());
        this.getContext().setForwardPathBuffer(smtpCommand.getForwardPathBuffer());
        this.getContext().setMailDataBuffer(smtpCommand.getMailDataBuffer());
    }
}
