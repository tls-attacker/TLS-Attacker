/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.serializer.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.Serializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNamePairSerializer extends Serializer<ServerNamePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerNamePair pair;

    public ServerNamePairSerializer(ServerNamePair pair) {
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
