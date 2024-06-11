package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SmtpMessagePreparator<MessageT extends SmtpMessage> extends Preparator<MessageT> {
    public SmtpMessagePreparator(Chooser chooser, MessageT object) {
        super(chooser, object);
    }

    @Override
    public void prepare() {

    }
}
