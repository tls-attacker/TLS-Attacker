/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

public class SmtpVRFYCommand extends SmtpCommand {

    private static final String COMMAND = "VRFY";
    private String username;
    private String mailboxAddress;

    // Constructor for malformed VRFY-commands, where too many/too little parameters are provided:
    public SmtpVRFYCommand(String parameters) {
        super(COMMAND, parameters);
    }

    public String getUsername() {
        return username;
    }

    public String getMailboxAddress() {
        return mailboxAddress;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setMailboxAddress(String mailboxAddress) {
        this.mailboxAddress = mailboxAddress;
    }
}
