package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;

public class SmtpCommandHandler extends SmtpMessageHandler<SmtpCommand> {

    private final SmtpContext smtpContext;

    public SmtpCommandHandler(SmtpContext smtpContext) {this.smtpContext = smtpContext;}

    @Override
    public void adjustContext(SmtpCommand smtpCommand) {
        smtpContext.setReversePathBuffer(smtpCommand.getReversePathBuffer());
        smtpContext.setForwardPathBuffer(smtpCommand.getForwardPathBuffer());
        smtpContext.setMailDataBuffer(smtpCommand.getMailDataBuffer());
    }
}
