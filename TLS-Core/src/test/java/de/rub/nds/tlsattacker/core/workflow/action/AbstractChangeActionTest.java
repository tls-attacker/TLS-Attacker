/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import org.junit.jupiter.api.Test;

abstract class AbstractChangeActionTest<T extends TlsAction> extends AbstractActionTest<T> {

    protected final TlsContext context;

    AbstractChangeActionTest(T action, Class<T> actionClass) {
        super(action, actionClass);
        context = state.getTlsContext();
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    }

    @Test
    public abstract void testGetNewValue();

    @Test
    public abstract void testSetNewValue();

    @Test
    public abstract void testGetOldValue();
}
