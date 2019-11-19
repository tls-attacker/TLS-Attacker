/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension.esni;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.protocol.message.extension.esni.ClientEncryptedSni;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;

public class ClientEncryptedSniSerializer extends Serializer<ClientEncryptedSni> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ClientEncryptedSni clientEncryptedSni;

    public ClientEncryptedSniSerializer(ClientEncryptedSni clientEncryptedSni) {
        this.clientEncryptedSni = clientEncryptedSni;
    }

    @Override
    protected byte[] serializeBytes() {
        // TODO Auto-generated method stub
        return null;
    }
}