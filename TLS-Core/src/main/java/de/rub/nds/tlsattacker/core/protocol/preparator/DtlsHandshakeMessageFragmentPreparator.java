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
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import static de.rub.nds.tlsattacker.core.protocol.preparator.Preparator.LOGGER;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

/**
 *
 * @author Robert Merget <robert.merget@rub.de>
 */
public class DtlsHandshakeMessageFragmentPreparator extends HandshakeMessagePreparator<DtlsHandshakeMessageFragment> {

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
        prepareFragmentLenth(msg);
        prepareMessageLength(msg.getContent().getValue().length);
    }

    @Override
    protected void prepareMessageLength(int length) {
        // TODO ....
        msg.setLength(msg.getContent().getValue().length);
    }

    private void prepareFragmentLenth(DtlsHandshakeMessageFragment msg) {
        // todo do proper
        msg.setFragmentLength(msg.getContent().getValue().length);
        LOGGER.debug("FragmentLength: " + msg.getFragmentLength().getValue());
    }

    private void prepareFragmentOffset(DtlsHandshakeMessageFragment msg) {
        msg.setFragmentOffset(0);
        LOGGER.debug("FragmentOffset: " + msg.getFragmentOffset().getValue());
    }

    private void prepareMessageSeq(DtlsHandshakeMessageFragment msg) {
        // TODO this should be flight seq
        msg.setMessageSeq((int) chooser.getContext().getWriteSequenceNumber());
        LOGGER.debug("MessageSeq: " + msg.getMessageSeq().getValue());
    }
}
