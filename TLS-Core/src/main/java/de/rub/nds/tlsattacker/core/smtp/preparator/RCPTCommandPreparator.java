package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpRCPTCommand;

public class RCPTCommandPreparator extends SmtpCommandPreparator<SmtpRCPTCommand> {
    public RCPTCommandPreparator(SmtpContext context, SmtpRCPTCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        this.getObject().setVerb("RCPT");
        String recipient = this.getObject().getParameters();
        this.getObject().setParameters("TO:<" + recipient + ">");
    }
}
