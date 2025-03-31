/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.extensions;

public class SmtpSMTPUTF8Extension extends SmtpServiceExtension {
    // yes the extension is called SMTPUTF8 (RFC5336), so the name is correct
    // also see UTF8SMTP
    public SmtpSMTPUTF8Extension() {
        super("SMTPUTF8");
    }
}
