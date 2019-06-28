/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.extension.sni.ServerNamePair;
import de.rub.nds.tlsattacker.core.protocol.preparator.Preparator;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerNamePairPreparator extends Preparator<ServerNamePair> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ServerNamePair pair;

    public ServerNamePairPreparator(Chooser chooser, ServerNamePair pair) {
        super(chooser, pair);
        this.pair = pair;
    }

    @Override
    public void prepare() {
        LOGGER.debug("Preparing ServerNamePairMessage");
        prepareServerName(pair);
        prepareServerNameType(pair);
        prepareServerNameLength(pair);
    }

    private void prepareServerName(ServerNamePair pair) {
        pair.setServerName(pair.getServerNameConfig());
        LOGGER.debug("ServerName: " + ArrayConverter.bytesToHexString(pair.getServerName().getValue()));
    }

    private void prepareServerNameType(ServerNamePair pair) {
        pair.setServerNameType(pair.getServerNameTypeConfig());
        LOGGER.debug("ServerNameType: " + pair.getServerNameType().getValue());
    }

    private void prepareServerNameLength(ServerNamePair pair) {
        pair.setServerNameLength(pair.getServerName().getValue().length);
        LOGGER.debug("ServerNameLength: " + pair.getServerNameLength().getValue());
    }

}
