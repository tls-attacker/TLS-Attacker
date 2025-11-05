/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.smtp.serializer;

import de.rub.nds.tlsattacker.core.layer.context.SmtpContext;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpCommand;
import de.rub.nds.tlsattacker.core.smtp.command.SmtpDATAContentCommand;

/**
 * Serializer for SMTP DATA content commands.
 * This is special, because the content does not have a keyword
 */
public class SmtpDATAContentCommandSerializer
        extends SmtpCommandSerializer<SmtpDATAContentCommand> {

    // modeled after their usage in RFC 5321
    private static final String SP = " ";
    private static final String CRLF = "\r\n";

    public SmtpDATAContentCommandSerializer(SmtpContext context, SmtpDATAContentCommand smtpCommand) {
        super(context, smtpCommand);
    }

    @Override
    protected byte[] serializeBytes() {
        StringBuilder sb = new StringBuilder();
        boolean parametersExist = this.command.getParameters() != null;

        if (parametersExist) {
            sb.append(this.command.getParameters());
        }

        sb.append(CRLF);
        byte[] output = sb.toString().getBytes();
        appendBytes(output);
        return getAlreadySerialized();
    }
}
