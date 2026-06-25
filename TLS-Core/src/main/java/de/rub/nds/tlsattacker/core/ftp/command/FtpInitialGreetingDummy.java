/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.command;

import de.rub.nds.tlsattacker.core.ftp.FtpCommandType;
import de.rub.nds.tlsattacker.core.ftp.FtpMessage;
import de.rub.nds.tlsattacker.core.ftp.handler.FtpCommandHandler;
import de.rub.nds.tlsattacker.core.ftp.parser.command.FtpCommandParser;
import de.rub.nds.tlsattacker.core.ftp.preparator.FtpCommandPreparator;
import de.rub.nds.tlsattacker.core.ftp.serializer.FtpCommandSerializer;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

/**
 * Dummy class necessary to process the InitialGreeting sent by the FTP server. It should not be
 * included in an actual workflow.
 */
public class FtpInitialGreetingDummy extends FtpCommand {

    public FtpInitialGreetingDummy() {
        super(FtpCommandType.INITIAL_GREETING, null);
    }

    @Override
    public FtpCommandParser<? extends FtpMessage> getParser(Context context, InputStream stream) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public FtpCommandPreparator<? extends FtpCommand> getPreparator(Context context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public FtpCommandSerializer<? extends FtpCommand> getSerializer(Context context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }

    @Override
    public FtpCommandHandler<? extends FtpMessage> getHandler(Context context) {
        throw new UnsupportedOperationException(
                "This is a dummy class that should not be included in a Workflow.");
    }
}
