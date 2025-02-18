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
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;

/**
 * Implements a handler for {@link SmtpCommand} objects.
 * <p>It implements the {@link SmtpMessageHandler#adjustContext adjustContext} method to always update the {@link SmtpContext} with a processed command which the {@link de.rub.nds.tlsattacker.core.layer.impl.SmtpLayer SmtpLayer} relies on.
 * Subclasses are therefore strongly advised to implement {@link SmtpCommandHandler#adjustContextSpecific(SmtpCommand) adjustContextSpecific} instead.
 * For messages that do not affect the context, this class acts as a default implementation.
 *
 * <p>Example for command:
 * After processing a {@link de.rub.nds.tlsattacker.core.smtp.command.SmtpMAILCommand SmtpMAILCommand} the {@link SmtpContext} should be updated with the given sender address in {@link SmtpContext#recipientBuffer recipientBuffer}.
 * @param <CommandT> the command object type
 *
 * @see de.rub.nds.tlsattacker.core.smtp.handler.SmtpMessageHandler
 * @see SmtpContext
 */
public class SmtpCommandHandler<CommandT extends SmtpCommand> extends SmtpMessageHandler<CommandT> {

    public SmtpCommandHandler(SmtpContext smtpContext) {
        super(smtpContext);
    }

    @Override
    public void adjustContext(CommandT smtpCommand) {
        this.context.setLastCommand(smtpCommand);
        adjustContextSpecific(smtpCommand);
    }

    /**
     * Adjusts the {@link SmtpContext} with the information from the command.
     * <p>Subclasses should override this method to update the {@link SmtpContext} with the information from the command.
     * @param smtpCommand the command to process
     */
    public void adjustContextSpecific(CommandT smtpCommand) {
        // empty, override if needed
    }
}
