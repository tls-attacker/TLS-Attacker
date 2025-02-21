package de.rub.nds.tlsattacker.core.smtp.preparator.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpAUTHCredentialsCommand;

public class AUTHCredentialsCommandPreparator extends SmtpCommandPreparator<SmtpAUTHCredentialsCommand> {
    public AUTHCredentialsCommandPreparator(SmtpContext context, SmtpAUTHCredentialsCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        if (this.getObject() != null && this.getObject().getCredentials() != null) {
            this.getObject().setParameters(this.getObject().getCredentials());
        } else {
            this.getObject().setParameters(chooser.getConfig().getDefaultSmtpAuthCredentials());
        }
    }
}
