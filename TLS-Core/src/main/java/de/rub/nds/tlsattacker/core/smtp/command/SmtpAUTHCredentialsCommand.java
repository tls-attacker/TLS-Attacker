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
import de.rub.nds.tlsattacker.core.smtp.SmtpCommandType;
import de.rub.nds.tlsattacker.core.smtp.parser.command.AUTHCredentialsParser;
import de.rub.nds.tlsattacker.core.smtp.preparator.command.AUTHCredentialsCommandPreparator;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpAUTHCredentialsCommandSerializer;
import de.rub.nds.tlsattacker.core.smtp.serializer.SmtpCommandSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;

/**
 * This class is designated to AUTH credentials that were sent as standalone messages. For single
 * line AUTH commands, an initial response can be provided instead.
 *
 * @see SmtpAUTHCommand
 */
@XmlRootElement
public class SmtpAUTHCredentialsCommand extends SmtpCommand {
    String credentials;

    public SmtpAUTHCredentialsCommand() {
        super(SmtpCommandType.AUTH_CREDENTIALS);
    }

    public SmtpAUTHCredentialsCommand(String credentials) {
        this.credentials = credentials;
    }

    public String getCredentials() {
        return credentials;
    }

    public void setCredentials(String credentials) {
        this.credentials = credentials;
    }

    @Override
    public AUTHCredentialsParser getParser(SmtpContext context, InputStream stream) {
        return new AUTHCredentialsParser(stream);
    }

    @Override
    public AUTHCredentialsCommandPreparator getPreparator(SmtpContext context) {
        return new AUTHCredentialsCommandPreparator(context, this);
    }

    @Override
    public SmtpCommandSerializer<? extends SmtpCommand> getSerializer(SmtpContext context) {
        return new SmtpAUTHCredentialsCommandSerializer(context, this);
    }
}
