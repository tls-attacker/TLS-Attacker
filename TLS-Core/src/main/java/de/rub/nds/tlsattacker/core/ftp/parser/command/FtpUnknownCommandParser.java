/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.parser.command;

import de.rub.nds.tlsattacker.core.ftp.command.FtpUnknownCommand;
import java.io.InputStream;

public class FtpUnknownCommandParser extends FtpCommandParser<FtpUnknownCommand> {

    public FtpUnknownCommandParser(InputStream stream) {
        super(stream);
    }

    /**
     * Special parser for unknown commands which also captures the verb string. Other parsers do not
     * have access to the verb string, because they are created based on the verb matching a known
     * keyword.
     *
     * @param ftpCommand the unknown command to populate
     */
    @Override
    public void parse(FtpUnknownCommand ftpCommand) {
        String line = parseSingleLine();
        String actualCommand = line.trim();
        String[] verbAndParams = actualCommand.split(" ", 2);

        ftpCommand.setUnknownCommandVerb(verbAndParams[0]);
        if (verbAndParams.length == 2) {
            ftpCommand.setArguments(verbAndParams[1]);
        }
    }
}
