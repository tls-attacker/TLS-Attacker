package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;

public class VRFYCommandPreparator extends SmtpCommandPreparator<SmtpVRFYCommand> {
    public VRFYCommandPreparator(SmtpContext context, SmtpVRFYCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        this.getCommand().setVerb("VRFY"); // TODO: check whether/how to set arguments as well
    }
}
