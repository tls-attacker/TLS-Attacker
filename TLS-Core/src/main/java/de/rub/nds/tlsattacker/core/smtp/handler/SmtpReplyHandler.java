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
import de.rub.nds.tlsattacker.core.smtp.reply.SmtpReply;

/**
 * Implements a handler for {@link SmtpReply} objects.
 *
 * <p>Subclasses of this class should implement the {@link SmtpReplyHandler#adjustContext
 * adjustContext} method to update the {@link SmtpContext} with the information from the reply. For
 * replies that do not affect the context, this class acts as a default implementation.
 *
 * <p>Example for replies: After processing a {@link
 * de.rub.nds.tlsattacker.core.smtp.reply.SmtpQUITReply SmtpQUITReply} the {@link SmtpContext}
 * should be updated with the information that the server acknowledged the close in {@link
 * SmtpContext#serverAcknowledgedClose serverAcknowledgedClose}.
 *
 * @param <ReplyT> the command object type
 * @see de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler
 * @see SmtpContext
 */
public class SmtpReplyHandler<ReplyT extends SmtpReply> extends SmtpMessageHandler<ReplyT> {
    public SmtpReplyHandler(SmtpContext smtpContext) {
        super(smtpContext.getContext());
    }

    @Override
    public void adjustContext(ReplyT smtpMessage) {}
}
