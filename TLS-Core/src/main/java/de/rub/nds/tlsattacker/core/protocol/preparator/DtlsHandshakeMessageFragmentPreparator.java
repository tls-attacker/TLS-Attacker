/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
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
        prepareFragmentOffset(msg);
        prepareMessageSeq(msg);
        if (msg.getContentConfig() != null) {
            msg.setContent(msg.getContentConfig());
        } else {
            msg.setContent(new byte[0]);
        }
        LOGGER.debug("FragmentContent:" + ArrayConverter.bytesToHexString(msg.getContent().getValue()));
        prepareFragmentLength(msg);
        prepareMessageLength(msg.getContent().getValue().length);
    }

    /*
     * We need to overwrite this method, since the message length in DTLS only
     * includes the content and does not include DTLS fragment headers. In the
     * base class, we supply the length of the serialized byte array which also
     * contains these headers.
     */
    @Override
    protected void prepareMessageLength(int length) {
        msg.setLength(msg.getContent().getValue().length);
    }

    private void prepareFragmentLength(DtlsHandshakeMessageFragment msg) {
        msg.setFragmentLength(msg.getContent().getValue().length);
        LOGGER.debug("FragmentLength: " + msg.getFragmentLength().getValue());
    }

    private void prepareFragmentOffset(DtlsHandshakeMessageFragment msg) {
        msg.setFragmentOffset(0);
        LOGGER.debug("FragmentOffset: " + msg.getFragmentOffset().getValue());
    }

    private void prepareMessageSeq(DtlsHandshakeMessageFragment msg) {
        // sending
        if (chooser.getContext().getTalkingConnectionEndType() == chooser.getContext().getChooser()
                .getConnectionEndType()) {
            msg.setMessageSeq((int) chooser.getContext().getDtlsCurrentSendSequenceNumber());
        }
        // receiving
        else {
            msg.setMessageSeq((int) chooser.getContext().getDtlsCurrentReceiveSequenceNumber());
        }
        LOGGER.debug("MessageSeq: " + msg.getMessageSeq().getValue());
    }
}
