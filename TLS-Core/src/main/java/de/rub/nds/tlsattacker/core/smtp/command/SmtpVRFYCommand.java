/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

/**
 * This class represents an SMTP VRFY command, which is used to verify whether an e-mail address exists.
 * The VRFY command can have the parameters: username OR mailboxAddress OR username and mailboxAddress.
 */
public class SmtpVRFYCommand extends SmtpCommand {

    private static final String COMMAND_NAME = "VRFY";
    private String username;
    private String mailboxAddress;

    public SmtpVRFYCommand(String parameters) {
        super(COMMAND_NAME, parameters);
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
