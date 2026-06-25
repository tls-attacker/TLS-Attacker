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
import de.rub.nds.tlsattacker.core.ftp.parser.command.FtpCommandParser;
import de.rub.nds.tlsattacker.core.ftp.parser.command.FtpUnknownCommandParser;
import de.rub.nds.tlsattacker.core.state.Context;
import java.io.InputStream;

public class FtpUnknownCommand extends FtpCommand {

    private String unknownCommandVerb = "";

    public FtpUnknownCommand() {
        super(FtpCommandType.UNKNOWN, null);
    }

    public String getUnknownCommandVerb() {
        return unknownCommandVerb;
    }

    public void setUnknownCommandVerb(String unknownCommandVerb) {
        this.unknownCommandVerb = unknownCommandVerb;
    }

    @Override
    public FtpCommandParser<? extends FtpMessage> getParser(Context context, InputStream stream) {
        return new FtpUnknownCommandParser(stream);
    }
}
