/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.workflow.action;

import de.rub.nds.tlsattacker.core.record.cipher.CipherState;
import de.rub.nds.tlsattacker.core.record.cipher.RecordNullCipher;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class DeactivateEncryptionAction extends DeactivateCryptoAction {

    @Override
    protected void deactivateCrypto(TlsContext tlsContext) {
        LOGGER.info("Disabling encryption");
        tlsContext.getRecordLayer().updateEncryptionCipher(
            new RecordNullCipher(tlsContext, new CipherState(tlsContext.getChooser().getSelectedProtocolVersion(),
                tlsContext.getChooser().getSelectedCipherSuite(), null, null, 0)));
    }

}
