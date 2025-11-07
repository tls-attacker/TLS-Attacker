/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpCommandParser;
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpUnknownCommandParser;
import de.rub.nds.tlsattacker.core.state.Context;

import java.io.InputStream;

public class SmtpUnknownCommand extends SmtpCommand {
    // Since the verb field is final,we cannot use them to store the unknown command value
    public String unknownCommandVerb = "";

    public SmtpUnknownCommand() {
        super(SmtpCommandType.UNKNOWN);
    }

    public String getUnknownCommandVerb() {
        return unknownCommandVerb;
    }

    @Override
    public SmtpCommandParser<? extends SmtpCommand> getParser(Context context, InputStream stream) {
        return new SmtpUnknownCommandParser(stream);
    }

    public void setUnknownCommandVerb(String unknownCommandVerb) {
        this.unknownCommandVerb = unknownCommandVerb;
    }

}
