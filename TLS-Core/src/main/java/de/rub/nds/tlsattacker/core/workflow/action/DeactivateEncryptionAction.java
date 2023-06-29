/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class DeactivateEncryptionAction extends DeactivateCryptoAction {

    @Override
    protected void deactivateCrypto(TlsContext tlsContext) {
        LOGGER.info("Disabling encryption");
        tlsContext
                .getRecordLayer()
                .updateEncryptionCipher(RecordCipherFactory.getNullCipher(tlsContext));
    }
}
