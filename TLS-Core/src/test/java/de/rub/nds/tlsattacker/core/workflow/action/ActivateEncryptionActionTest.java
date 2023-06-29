/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import static org.junit.jupiter.api.Assertions.assertFalse;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.impl.RecordLayer;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import org.junit.jupiter.api.Test;

public class ActivateEncryptionActionTest extends AbstractActionTest<ActivateEncryptionAction> {

    private final TlsContext context;

    public ActivateEncryptionActionTest() {
        super(new ActivateEncryptionAction(), ActivateEncryptionAction.class);
        context = state.getTlsContext();
        context.setSelectedCipherSuite(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
    }

    @Test
    @Override
    public void testExecute() throws Exception {
        super.testExecute();
        RecordLayer layer = context.getRecordLayer();
        assertFalse(layer.getEncryptorCipher() instanceof RecordNullCipher);
    }
}
