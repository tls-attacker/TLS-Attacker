package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class EHLOPreparator extends SmtpCommandPreparator<SmtpEHLOCommand> {
    public EHLOPreparator(SmtpContext context, SmtpEHLOCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        this.getCommand().setVerb("EHLO");
    }
}
