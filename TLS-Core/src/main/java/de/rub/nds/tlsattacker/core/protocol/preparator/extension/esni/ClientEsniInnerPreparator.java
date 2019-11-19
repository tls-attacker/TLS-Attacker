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
import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEsniInner;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class ClientEsniInnerPreparator extends Preparator<ClientEsniInner> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ClientEsniInner clientEsniInner;

    public ClientEsniInnerPreparator(Chooser chooser, ClientEsniInner clientEsniInner) {
        super(chooser, clientEsniInner);
        this.clientEsniInner = clientEsniInner;
        // TODO Auto-generated constructor stub
    }

    @Override
    public void prepare() {
        // TODO Auto-generated method stub

        // PaddedServerNameList :=
        // + ServerNameList sni;
        // + opaque zeros[ESNIKeys.padded_length - length(sni)];

        // ClientEsniInner :=
        // + uint8 nonce[16];
        // + PaddedServerNameList realSNI;

    }

}
