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
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "ActivateEncryption")
public class ActivateEncryptionAction extends ActivateCryptoAction {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void activateCrypto(TlsContext tlsContext, RecordCipher recordCipher) {
        LOGGER.info("Setting new encryption cipher and activating encryption");
        tlsContext.getRecordLayer().updateEncryptionCipher(recordCipher);
    }
}
