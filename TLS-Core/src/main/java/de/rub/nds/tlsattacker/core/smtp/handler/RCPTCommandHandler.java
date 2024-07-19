package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpRCPTCommand;
import java.util.ArrayList;
import java.util.List;

public class RCPTCommandHandler extends SmtpCommandHandler<SmtpRCPTCommand> {
    public RCPTCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContextSpecific(SmtpRCPTCommand smtpRCPTCommand) {
        List<String> recipients = this.getContext().getRecipientBuffer();
        recipients.add(smtpRCPTCommand.getRecipient());
        this.getContext().setRecipientBuffer(recipients);
    }
}
