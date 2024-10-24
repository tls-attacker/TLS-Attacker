/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.command;

import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Represents the DATA command of the SMTP protocol, used for sending actual mail strings.
 * This command models the first half of the interaction, which simply initiates the data transfer.
 * The data transfer itself is performed by {@link SmtpDATAContentCommand}.
 * Example:
 * <p>C: DATA</p>
 * <p>S: 354 Start mail input; end with &lt;CRLF&gt;.&lt;CRLF&gt;</p>
 * <p>C: Blah blah blah...</p>
 * <p>C: ...etc. etc. etc.</p>
 * <p>C: .</p>
 * <p>S: 250 OK</p>
 * @see de.rub.nds.tlsattacker.core.smtp.command.SmtpDATAContentCommand
 */
@XmlRootElement
public class SmtpDATACommand extends SmtpCommand {
    private static final String COMMAND = "DATA";

    public SmtpDATACommand() {
        super(COMMAND, null);
    }
}
