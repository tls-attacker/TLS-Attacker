package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;

public class EHLOCommandHandler extends SmtpCommandHandler<SmtpEHLOCommand> {
    public EHLOCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContextSpecific(SmtpEHLOCommand smtpCommand) {
        this.getContext().setClientIdentity(smtpCommand.getClientIdentity());
    }
}
