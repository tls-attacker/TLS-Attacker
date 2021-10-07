/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.record.cipher.RecordCipher;
import de.rub.nds.tlsattacker.core.record.cipher.RecordCipherFactory;
import de.rub.nds.tlsattacker.core.record.cipher.cryptohelper.KeySet;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class ActivateEncryptionAction extends ActivateCryptoAction {

    @Override
    protected void activateCrypto(TlsContext tlsContext, KeySet keySet) {
        LOGGER.info("Setting new encryption cipher and activating encryption");
        RecordCipher recordCipher = RecordCipherFactory.getRecordCipher(tlsContext, keySet, true);
        tlsContext.getRecordLayer().updateEncryptionCipher(recordCipher);
    }

}
