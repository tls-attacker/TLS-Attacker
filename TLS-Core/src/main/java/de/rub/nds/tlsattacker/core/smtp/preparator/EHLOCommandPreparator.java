package de.rub.nds.tlsattacker.core.smtp.preparator;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;

public class EHLOCommandPreparator extends SmtpCommandPreparator<SmtpEHLOCommand> {
    public EHLOCommandPreparator(SmtpContext context, SmtpEHLOCommand command) {
        super(context.getChooser(), command);
    }

    @Override
    public void prepare() {
        this.getObject().setVerb("EHLO");
        if(this.getObject().hasAddressLiteral()) {
            this.getObject().setParameters("[" + this.getObject().getDomain() + "]");
        } else {
            this.getObject().setParameters(this.getObject().getDomain());
        }
    }
}
