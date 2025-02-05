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
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3USERCommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.USERCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This command is used alongside the Pop3PASSCommand as a basic means of authentication.
 */
@XmlRootElement
public class Pop3USERCommand extends Pop3Command {
    private String username;

    private static final String commandName = "USER";

    public Pop3USERCommand() {
        super(commandName);
    }

    public Pop3USERCommand(String username) {
        super(commandName, username);
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getCommandName() {
        return commandName;
    }

    @Override
    public Pop3USERCommandParser getParser(Pop3Context context, InputStream stream) {
        return new Pop3USERCommandParser(stream);
    }

    @Override
    public USERCommandPreparator getPreparator(Pop3Context context) {
        return new USERCommandPreparator(context, this);
    }
}
