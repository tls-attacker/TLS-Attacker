/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension.esni;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEncryptedSni;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ClientEncryptedSniPreparator extends Preparator<ClientEncryptedSni> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ClientEncryptedSni clientEncryptedSni;

    public ClientEncryptedSniPreparator(Chooser chooser, ClientEncryptedSni clientEncryptedSni) {
        super(chooser, clientEncryptedSni);
        this.clientEncryptedSni = clientEncryptedSni;
    }

    @Override
    public void prepare() {
        // TODO Auto-generated method stub

        // ClientEncryptedSni :=
        // + CipherSuite suite;
        // + KeyShareEntry key_share;
        // + opaque record_digest<0..2^16-1>;
        // + opaque encrypted_sni<0..2^16-1>,
        // ->Encryption of ClientEsniInnerBytes
        // + ClientESNIInner
    }

}
