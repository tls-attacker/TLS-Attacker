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

/**
 * This class serializes SMTP commands. Typically, a command is serialized in the format
 * "COMMAND&lt;SP&gt;[PARAMETERS]&lt;CRLF&gt;". Where &lt;SP&gt; is a space character and
 * &lt;CRLF&gt; is a carriage return followed by a line feed. When there are no parameters, the
 * command is serialized as "COMMAND&lt;CRLF&gt;". This is according to the SMTP protocol as defined
 * in RFC 5321.
 */
public class SmtpCommandSerializer<CommandT extends SmtpCommand>
        extends SmtpMessageSerializer<CommandT> {

    // modeled after their usage in RFC 5321
    private static final String SP = " ";
    private static final String CRLF = "\r\n";

    private final SmtpCommand command;

    public SmtpCommandSerializer(SmtpContext context, CommandT smtpCommand) {
        super(smtpCommand, context);
        this.command = smtpCommand;
    }

    @Override
    protected byte[] serializeBytes() {
        StringBuilder sb = new StringBuilder();

        boolean verbExists = this.command.getVerb() != null;
        boolean parametersExist = this.command.getParameters() != null;

        if (verbExists) sb.append(this.command.getVerb());
        if (verbExists && parametersExist) sb.append(SP);
        if (parametersExist) sb.append(this.command.getParameters());

        sb.append(CRLF);
        byte[] output = sb.toString().getBytes();
        appendBytes(output);
        return getAlreadySerialized();
    }
}
