/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.command;

import de.rub.nds.tlsattacker.core.pop3.Pop3CommandType;
import de.rub.nds.tlsattacker.core.pop3.Pop3Message;
import de.rub.nds.tlsattacker.core.pop3.handler.Pop3CommandHandler;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.Pop3CommandPreparator;
import de.rub.nds.tlsattacker.core.pop3.serializer.Pop3CommandSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

/**
 * This is a dummy class that is necessary to process the InitialGreeting sent by the POP3 Server.
 * It should not be included in an actual workflow.
 */
public class Pop3InitialGreetingDummy extends Pop3Command {

    public Pop3InitialGreetingDummy() {
        super(Pop3CommandType.INITIAL_GREETING, null);
    }

    @Override
    public Pop3CommandParser<? extends Pop3Message> getParser(Context context, InputStream stream) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public Pop3CommandPreparator<? extends Pop3Command> getPreparator(Context context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public Pop3CommandSerializer<? extends Pop3Command> getSerializer(Context context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public Pop3CommandHandler<? extends Pop3Message> getHandler(Context context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }
}
