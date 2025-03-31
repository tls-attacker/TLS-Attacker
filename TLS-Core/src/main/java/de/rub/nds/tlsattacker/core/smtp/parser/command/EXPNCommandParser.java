/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.parser.command;

import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpEXPNCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpVRFYCommand;
import java.io.InputStream;

public class EXPNCommandParser extends SmtpCommandParser<SmtpEXPNCommand> {
    public EXPNCommandParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parseArguments(SmtpEXPNCommand expnCommand, String parameter) {
        if (parameter == null) {
            throw new ParserException("EXPN-Parameter can't be null.");
        }

        // Use VRFY-Parser due to identical input:
        SmtpVRFYCommand vrfyCommand = new SmtpVRFYCommand();
        VRFYCommandParser vrfyCommandParser = new VRFYCommandParser(null);
        vrfyCommandParser.parseArguments(vrfyCommand, parameter);

        expnCommand.setMailingList(vrfyCommand.getUsername());
    }
}
