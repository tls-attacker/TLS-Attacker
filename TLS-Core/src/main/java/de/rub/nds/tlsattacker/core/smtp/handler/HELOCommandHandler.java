package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpHELOCommand;

public class HELOCommandHandler extends SmtpCommandHandler<SmtpHELOCommand> {
    public HELOCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContextSpecific(SmtpHELOCommand smtpCommand) {
        this.getContext().setClientIdentity(smtpCommand.getDomain());
    }
}
