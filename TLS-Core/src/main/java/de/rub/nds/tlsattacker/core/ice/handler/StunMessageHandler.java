/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.handler;

import de.rub.nds.tlsattacker.core.ice.model.StunMessage;
import de.rub.nds.tlsattacker.core.layer.context.IceContext;
import de.rub.nds.tlsattacker.core.layer.data.Handler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StunMessageHandler extends Handler<StunMessage> {

    protected static final Logger LOGGER = LogManager.getLogger();
    /** context */
    protected final IceContext iceContext;

    public StunMessageHandler(IceContext iceContext) {
        this.iceContext = iceContext;
    }

    @Override
    public void adjustContext(StunMessage container) {
        // TODO: maybe we need to keep context?
    }
}
