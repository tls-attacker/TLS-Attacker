/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.command;

public class PASSCommand extends Pop3Command {
    private String password;
    private static final String commandName = "PASS";

    public PASSCommand() {
        super(commandName);
    }

    public PASSCommand(String password) {
        super(commandName, password);
        this.password = password;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public String getCommandName() {
        return commandName;
    }
}
