/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.extensions;

public class SmtpNO_SOLICITINGExtension extends SmtpServiceExtension {
    // TODO: Implement, so far this just enables SmtpEHLOReplyParser to read it
    private String parameters;

    public SmtpNO_SOLICITINGExtension(String parameters) {
        super("NO-SOLICITING");
        this.parameters = parameters;
    }
}
