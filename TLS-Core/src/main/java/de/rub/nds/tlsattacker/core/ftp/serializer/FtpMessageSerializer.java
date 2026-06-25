/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ftp.serializer;

import de.rub.nds.tlsattacker.core.ftp.FtpMessage;
import de.rub.nds.tlsattacker.core.layer.context.FtpContext;
import de.rub.nds.tlsattacker.core.layer.data.Serializer;

public abstract class FtpMessageSerializer<MessageT extends FtpMessage>
        extends Serializer<MessageT> {

    protected final MessageT message;
    protected final FtpContext context;

    public FtpMessageSerializer(MessageT message, FtpContext context) {
        this.message = message;
        this.context = context;
    }

    public MessageT getMessage() {
        return message;
    }

    public FtpContext getContext() {
        return context;
    }
}
