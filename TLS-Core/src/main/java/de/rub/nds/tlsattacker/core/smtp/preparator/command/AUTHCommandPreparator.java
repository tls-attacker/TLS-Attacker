package de.rub.nds.tlsattacker.core.smtp.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpAUTHCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;

public class AUTHCommandPreparator extends SmtpCommandPreparator<SmtpAUTHCommand> {

    public AUTHCommandPreparator(SmtpContext context, SmtpAUTHCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        this.getObject().setVerb("AUTH");
        this.getObject().setParameters(this.getObject().getSaslMechanism() + " " + this.getObject().getInitialResponse());
    }
}
