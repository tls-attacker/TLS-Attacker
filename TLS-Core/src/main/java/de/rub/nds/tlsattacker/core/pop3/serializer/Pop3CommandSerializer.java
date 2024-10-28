/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.pop3.serializer;

import de.rub.nds.tlsattacker.core.layer.context.Pop3Context;
import de.rub.nds.tlsattacker.core.pop3.command.Pop3Command;

/**
 * Serializes Pop3 Commands. Commands are serialized in the form "KEYWORD<SP>[ARGUMENTS]<CRLF>" The
 * Arguments are optional without them the command becomes: "KEYWORD<CRLF>"
 *
 * @param <CommandT> the Pop3 Command to serialize
 */
public class Pop3CommandSerializer<CommandT extends Pop3Command>
        extends Pop3MessageSerializer<CommandT> {

    private static final String SP = " ";
    private static final String CRLF = "\r\n";

    private final Pop3Command command;

    public Pop3CommandSerializer(CommandT pop3Command, Pop3Context context) {
        super(pop3Command, context);
        this.command = pop3Command;
    }

    @Override
    protected byte[] serializeBytes() {
        StringBuilder sb = new StringBuilder();

        boolean keywordExists = this.command.getKeyword() != null;
        boolean argumentsExist = this.command.getArguments() != null;

        if (keywordExists) sb.append(this.command.getKeyword());
        if (keywordExists && argumentsExist) sb.append(SP);
        if (argumentsExist) sb.append(this.command.getArguments());

        sb.append(CRLF);
        byte[] output = sb.toString().getBytes();
        appendBytes(output);
        return getAlreadySerialized();
    }
}
