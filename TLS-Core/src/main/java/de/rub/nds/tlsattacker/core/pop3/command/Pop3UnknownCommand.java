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
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3UnknownCommandParser;
import de.rub.nds.tlsattacker.core.state.Context;

import java.io.InputStream;

public class Pop3UnknownCommand extends Pop3Command {
    public String getUnknownCommandVerb() {
        return unknownCommandVerb;
    }

    public void setUnknownCommandVerb(String unknownCommandVerb) {
        this.unknownCommandVerb = unknownCommandVerb;
    }

    @Override
    public Pop3CommandParser<? extends Pop3Message> getParser(Context context, InputStream stream) {
        return new Pop3UnknownCommandParser(stream);
    }

    public String unknownCommandVerb = "";
    public Pop3UnknownCommand() {
        super(Pop3CommandType.UNKNOWN, null);
    }
}
