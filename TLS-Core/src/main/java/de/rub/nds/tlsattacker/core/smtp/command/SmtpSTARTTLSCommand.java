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

@XmlRootElement
/**
 * This implements the STARTTLS command, which is used to start a TLS session. It does not execute
 * the actual handshake, but communicates to the server that a TLS handshake is coming. Works hand
 * in hand with {@link de.rub.nds.tlsattacker.core.workflow.action.STARTTLSAction}. Example:
 *
 * <pre>
 * C: STARTTLS
 * S: 220 2.0.0 Ready to start TLS
 * </pre>
 *
 * @see de.rub.nds.tlsattacker.core.workflow.action.STARTTLSAction
 */
public class SmtpSTARTTLSCommand extends SmtpCommand {
    public SmtpSTARTTLSCommand() {
        super("STARTTLS");
    }
}
