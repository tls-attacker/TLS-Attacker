/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.parser.VRFYCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.VRFYCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.io.InputStream;

/**
 * This class represents an SMTP VRFY command, which is used to verify whether an e-mail address
 * exists. The VRFY command can have the parameters: username OR mailboxAddress OR username and
 * mailboxAddress.
 */
@XmlRootElement
public class SmtpVRFYCommand extends SmtpCommand {

    private static final String COMMAND_NAME = "VRFY";
    private String username;

    public SmtpVRFYCommand() {
        super(COMMAND_NAME, null);
    }

    public SmtpVRFYCommand(String username) {
        super(COMMAND_NAME, username);
        this.username = username;

    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public VRFYCommandParser getParser(SmtpContext context, InputStream stream) {
        return new VRFYCommandParser(stream);
    }

    @Override
    public VRFYCommandPreparator getPreparator(SmtpContext context) {
        return new VRFYCommandPreparator(context, this);
    }
}
