package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand;

public class SmtpMAILHandler extends SmtpCommandHandler<SmtpMAILCommand> {
    public SmtpMAILHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContext(SmtpCommand smtpCommand) {
        this.getContext().setReversePathBuffer(smtpCommand.getReversePathBuffer());
        this.getContext().setForwardPathBuffer(smtpCommand.getForwardPathBuffer());
        this.getContext().setMailDataBuffer(smtpCommand.getMailDataBuffer());
    }
}
