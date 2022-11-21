/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeCipherSpecPreparator extends TlsMessagePreparator<ChangeCipherSpecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final byte CCS_PROTOCOL_TYPE = 1;
    private final ChangeCipherSpecMessage msg;

    public ChangeCipherSpecPreparator(Chooser chooser, ChangeCipherSpecMessage message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        LOGGER.debug("Preparing ChangeCipherSpecMessage");
        prepareCcsProtocolType(msg);
    }

    private void prepareCcsProtocolType(ChangeCipherSpecMessage msg) {
        msg.setCcsProtocolType(new byte[] { CCS_PROTOCOL_TYPE });
        LOGGER.debug("CCSProtocollType: " + ArrayConverter.bytesToHexString(msg.getCcsProtocolType().getValue()));
    }

}
