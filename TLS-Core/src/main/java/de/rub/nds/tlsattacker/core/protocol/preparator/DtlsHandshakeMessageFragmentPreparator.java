/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DtlsHandshakeMessageFragmentPreparator extends HandshakeMessagePreparator<DtlsHandshakeMessageFragment> {

    private static final Logger LOGGER = LogManager.getLogger();

    private DtlsHandshakeMessageFragment msg;

    public DtlsHandshakeMessageFragmentPreparator(Chooser chooser, DtlsHandshakeMessageFragment message) {
        super(chooser, message);
        this.msg = message;
    }

    @Override
    protected void prepareHandshakeMessageContents() {
        msg.setContent(msg.getFragmentContentConfig());
        msg.setMessageSeq(msg.getMessageSequenceConfig());
        msg.setFragmentOffset(msg.getOffsetConfig());
        msg.setFragmentLength(msg.getHandshakeMessageLengthConfig());
        msg.setEpoch(chooser.getContext().getDtlsWriteEpoch());
    }

    @Override
    protected void prepareMessageLength(int length) {
        LOGGER.debug("Setting length of DtlsHandshakeMessage fragment to: " + msg.getContent().getValue().length);
        this.msg.setLength(msg.getContent().getValue().length);
    }

}
