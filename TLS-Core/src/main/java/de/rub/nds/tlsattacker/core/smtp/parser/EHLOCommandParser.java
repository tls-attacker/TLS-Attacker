/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser;

import de.rub.nds.tlsattacker.core.smtp.command.SmtpEHLOCommand;
import java.io.InputStream;
import org.bouncycastle.util.IPAddress;

public class EHLOCommandParser extends SmtpCommandParser<SmtpEHLOCommand> {
    public EHLOCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parseArguments(SmtpEHLOCommand command, String arguments) {
        if (IPAddress.isValid(arguments)) {
            command.setHasAddressLiteral(true);
        }
        command.setDomain(arguments);
    }

    @Override
    public boolean hasParameters() {
        return true;
    }
}
