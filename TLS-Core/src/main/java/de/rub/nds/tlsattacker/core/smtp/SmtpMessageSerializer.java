package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.data.Serializer;

public abstract class SmtpMessageSerializer<MessageT extends SmtpMessage> extends Serializer<MessageT> {

    protected final MessageT message;

    public SmtpMessageSerializer(MessageT message) {
        this.message = message;
    }
}
