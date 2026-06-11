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
import de.rub.nds.tlsattacker.core.pop3.parser.command.Pop3PASSCommandParser;
import de.rub.nds.tlsattacker.core.pop3.preparator.command.Pop3PASSCommandPreparator;
import de.rub.nds.tlsattacker.core.state.Context;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/** This command is used alongside the Pop3USERCommand as a basic means of authentication. */
@XmlRootElement
public class Pop3PASSCommand extends Pop3Command {
    private String password;

    public Pop3PASSCommand(String password) {
        super(Pop3CommandType.PASS, password);
        this.password = password;
    }

    public Pop3PASSCommand() {
        super(Pop3CommandType.PASS, null);
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public Pop3PASSCommandParser getParser(Context context, InputStream stream) {
        return new Pop3PASSCommandParser(stream);
    }

    @Override
    public Pop3PASSCommandPreparator getPreparator(Context context) {
        return new Pop3PASSCommandPreparator(context.getPop3Context(), this);
    }
}
