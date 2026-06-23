/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.serializer;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;

public abstract class SmtpMessageSerializer<MessageT extends SmtpMessage>
        extends Serializer<MessageT> {

    protected final MessageT message;
    protected final SmtpContext context;

    public SmtpMessageSerializer(MessageT message, SmtpContext context) {
        this.message = message;
        this.context = context;
    }

    public MessageT getMessage() {
        return message;
    }

    public SmtpContext getContext() {
        return context;
    }
}
