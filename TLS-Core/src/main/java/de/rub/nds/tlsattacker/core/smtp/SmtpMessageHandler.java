package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.data.Handler;

public abstract class SmtpMessageHandler<MessageT extends SmtpMessage> extends Handler<MessageT> {
    public void adjustContext(MessageT container) {

    }
}
