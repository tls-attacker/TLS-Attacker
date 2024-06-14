/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp;

import de.rub.nds.tlsattacker.core.layer.data.Parser;
import java.io.InputStream;

public abstract class SmtpMessageParser<MessageT extends SmtpMessage> extends Parser<MessageT> {
    /**
     * Constructor for the Parser
     *
     * @param stream The Inputstream to read data from
     */
    public SmtpMessageParser(InputStream stream) {
        super(stream);
    }
}
