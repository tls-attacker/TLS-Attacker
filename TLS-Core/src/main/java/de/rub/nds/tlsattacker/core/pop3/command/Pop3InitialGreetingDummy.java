/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.handler.Pop3CommandHandler;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3CommandSerializer;
import java.io.InputStream;

public class Pop3InitialGreetingDummy extends Pop3Command {

    @Override
    public Pop3CommandParser<? extends Pop3Message> getParser(
            Pop3Context context, InputStream stream) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public Pop3CommandPreparator<? extends Pop3Command> getPreparator(Pop3Context context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public Pop3CommandSerializer<? extends Pop3Command> getSerializer(Pop3Context context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public Pop3CommandHandler<? extends Pop3Message> getHandler(Pop3Context smtpContext) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }
}
