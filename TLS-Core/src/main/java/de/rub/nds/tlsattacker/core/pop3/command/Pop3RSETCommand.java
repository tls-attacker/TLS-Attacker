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
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3CommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.RSETCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * POP3 Servers use this command to revert deletion of messages.
 */

@XmlRootElement
public class Pop3RSETCommand extends Pop3Command {
    private static final String commandName = "RSET";

    public Pop3RSETCommand() {
        super(commandName, null);
    }

    @Override
    public Pop3CommandParser<Pop3RSETCommand> getParser(Pop3Context context, InputStream stream) {
        return new Pop3CommandParser<>(stream);
    }

    @Override
    public RSETCommandPreparator getPreparator(Pop3Context context) {
        return new RSETCommandPreparator(context, this);
    }

    @Override
    public String getCommandName() {
        return commandName;
    }
}
