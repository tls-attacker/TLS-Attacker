/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.SmtpMessage;
import de.rub.nds.tlsattacker.core.smtp.handler.SmtpCommandHandler;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpCommandSerializer;
import java.io.InputStream;

/**
 * This class represents the initial greeting of the SMTP server when a connection is established.
 * Its only use is to be able to distinguish between the initial greeting and truly unknown commands
 * when `receiving` in SmtpLayer. It should never be included in a Workflow.
 */
public class SmtpInitialGreetingDummy extends SmtpCommand {
    @Override
    public SmtpCommandParser<? extends SmtpMessage> getParser(
            SmtpContext context, InputStream stream) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public SmtpCommandPreparator<? extends SmtpCommand> getPreparator(SmtpContext context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public SmtpCommandSerializer<? extends SmtpCommand> getSerializer(SmtpContext context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public SmtpCommandHandler<? extends SmtpMessage> getHandler(SmtpContext smtpContext) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }
}
