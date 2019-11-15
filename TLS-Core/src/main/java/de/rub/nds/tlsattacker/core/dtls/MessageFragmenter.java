/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.util.Arrays;

/**
 * Class used to split HandshakeMessages into DTLS fragments.
 */
public class MessageFragmenter {

    private Integer maxFragmentLength;

    public MessageFragmenter(Config config) {
        maxFragmentLength = config.getDtlsMaximumFragmentLength();
    }

    /**
     * Takes a message and splits it into prepared fragments.
     */
    public List<DtlsHandshakeMessageFragment> fragmentMessage(HandshakeMessage message, TlsContext context) {
        HandshakeMessageSerializer serializer = (HandshakeMessageSerializer) message.getHandler(context).getSerializer(
                message);
        byte[] bytes = serializer.serializeHandshakeMessageContent();
        List<DtlsHandshakeMessageFragment> dtlsFragments = generateFragments(message, bytes, maxFragmentLength, context);
        return dtlsFragments;
    }

    /**
     * Generates a single fragment carrying the contents of the message as
     * payload.
     */
    public DtlsHandshakeMessageFragment wrapInSingleFragment(HandshakeMessage message, TlsContext context) {
        HandshakeMessageSerializer serializer = (HandshakeMessageSerializer) message.getHandler(context).getSerializer(
                message);
        byte[] bytes = serializer.serializeHandshakeMessageContent();
        List<DtlsHandshakeMessageFragment> fragments = generateFragments(message, bytes, bytes.length, context);
        return fragments.get(0);
    }

    private List<DtlsHandshakeMessageFragment> generateFragments(HandshakeMessage message, byte[] handshakeBytes,
            int maxFragmentLength, TlsContext context) {
        List<DtlsHandshakeMessageFragment> fragments = new LinkedList<>();
        int currentOffset = 0;
        do {
            System.out.println("Fragmenting:");
            System.out.println("Type" + message.toCompactString());
            System.out.println("Fragmenting:" + message.getMessageSequence().getValue());
            byte[] fragmentBytes = Arrays.copyOfRange(handshakeBytes, currentOffset,
                    Math.min(currentOffset + maxFragmentLength, handshakeBytes.length));
            DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment(message.getHandshakeMessageType(),
                    fragmentBytes, message.getMessageSequence().getValue(), currentOffset, handshakeBytes.length);
            fragment.getHandler(context).prepareMessage(fragment);
            fragments.add(fragment);
            currentOffset += maxFragmentLength;
        } while (currentOffset < handshakeBytes.length);

        return fragments;
    }
}
