/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.handler;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;

/**
 * Super class for handlers of SMTP messages.
 * The handler is invoked whenever a message is processed by the (Smtp)Layer - see {@link de.rub.nds.tlsattacker.core.layer.ProtocolLayer#readDataContainer readDataContainer}.
 * It should be used to adjust the {@link de.rub.nds.tlsattacker.core.layer.context.SmtpContext SmtpContext} based on the message contents.
 *
 * @param <MessageT> The type of message a handler is responsible for.
 */
public abstract class SmtpMessageHandler<MessageT extends SmtpMessage> extends Handler<MessageT> {

    protected final SmtpContext context;

    /**
     * Creates a new SmtpMessageHandler with the given SmtpContext.
     * As the handler is responsible for changes to the context, it will always need one.
     * @param context The SmtpContext to be used by the handler.
     */
    public SmtpMessageHandler(SmtpContext context) {
        this.context = context;
    }

    /**
     * Adjusts the {@link SmtpContext} based on the given message.
     * This method should be overridden by subclasses to implement the specific adjustments needed for a given message.
     * @param container The message (type given by the handler class) to adjust the context with.
     */
    @Override
    public void adjustContext(MessageT container) {}

    public SmtpContext getContext() {
        return context;
    }
}
