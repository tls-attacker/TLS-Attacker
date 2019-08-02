/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNamePairSerializier extends Serializer<ServerNamePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerNamePair pair;

    public ServerNamePairSerializier(ServerNamePair pair) {
        this.pair = pair;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing ServerNamePair");
        writeServerNameType(pair);
        writeServerNameLength(pair);
        writeServerName(pair);
        return getAlreadySerialized();
    }

    private void writeServerNameType(ServerNamePair pair) {
        appendByte(pair.getServerNameType().getValue());
        LOGGER.debug("ServerNameType: " + pair.getServerNameType().getValue());
    }

    private void writeServerNameLength(ServerNamePair pair) {
        appendInt(pair.getServerNameLength().getValue(), ExtensionByteLength.SERVER_NAME);
        LOGGER.debug("ServerNameLength: " + pair.getServerNameLength().getValue());
    }

    private void writeServerName(ServerNamePair pair) {
        appendBytes(pair.getServerName().getValue());
        LOGGER.debug("ServerName: " + ArrayConverter.bytesToHexString(pair.getServerName().getValue()));
    }

}
