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
import de.rub.nds.tlsattacker.core.smtp.parser.command.SmtpVRFYCommandParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.SmtpVRFYCommandPreparator;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This class represents an SMTP VRFY command, which is used to verify whether a user exists: <br>
 *
 * <pre>
 * C: VRFY jane
 * S: 250 Jane Doe &lt;jane.doe@upb.de&gt;
 * </pre>
 */
@XmlRootElement
public class SmtpVRFYCommand extends SmtpCommand {

    private static final String COMMAND_NAME = "VRFY";
    private String username;

    public SmtpVRFYCommand() {
        super(COMMAND_NAME);
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
    public SmtpVRFYCommandParser getParser(SmtpContext context, InputStream stream) {
        return new SmtpVRFYCommandParser(stream);
    }

    @Override
    public SmtpVRFYCommandPreparator getPreparator(SmtpContext context) {
        return new SmtpVRFYCommandPreparator(context, this);
    }
}
