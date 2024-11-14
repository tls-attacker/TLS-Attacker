/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.handler;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2Message;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SSL2MessageHandler<MessageT extends SSL2Message> extends Handler<MessageT> {

    protected static final Logger LOGGER = LogManager.getLogger();
    /** context */
    protected final TlsContext tlsContext;

    public SSL2MessageHandler(TlsContext tlsContext) {
        this.tlsContext = tlsContext;
    }

    public void updateDigest(MessageT message, boolean goingToBeSent) {
        tlsContext.getDigest().append(message.getCompleteResultingMessage().getValue());
        LOGGER.debug("Included in digest: {}", message.toCompactString());
    }

    public void adjustContextAfterSerialize(MessageT message) {}

    public void adjustContextBeforeParse(MessageT message) {}

    public void adjustContextAfterParse(MessageT message) {}

    public void adjustContextAfterPrepare(MessageT message) {}

    public void adjustContextBeforePrepare(MessageT message) {}
}
