/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;

import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import org.bouncycastle.util.Arrays;

/**
 * Class used to split HandshakeMessages into DTLS fragments.
 */
public class MessageFragmenter {

    /**
     * Takes a message and splits it into prepared fragments.
     */
    public static List<DtlsHandshakeMessageFragment> fragmentMessage(HandshakeMessage message, int maxFragmentLength,
        TlsContext context) {
        HandshakeMessageHandler<HandshakeMessage> handler = message.getHandler(context);
        HandshakeMessageSerializer<HandshakeMessage> serializer = handler.getSerializer(message);
        byte[] bytes = serializer.serializeHandshakeMessageContent();
        List<DtlsHandshakeMessageFragment> dtlsFragments =
            generateFragments(message, bytes, maxFragmentLength, context);
        return dtlsFragments;
    }

    /**
     * Takes a message and splits it into prepared fragments.
     */
    public static List<DtlsHandshakeMessageFragment> fragmentMessage(HandshakeMessage message,
        List<DtlsHandshakeMessageFragment> fragments, TlsContext context) {
        HandshakeMessageHandler<HandshakeMessage> handler = message.getHandler(context);
        HandshakeMessageSerializer<HandshakeMessage> serializer = handler.getSerializer(message);
        byte[] bytes = serializer.serializeHandshakeMessageContent();
        List<DtlsHandshakeMessageFragment> dtlsFragments = generateFragments(message, bytes, fragments, context);
        return dtlsFragments;
    }

    /**
     * Generates a single fragment carrying the contents of the message as payload.
     */
    public static DtlsHandshakeMessageFragment wrapInSingleFragment(HandshakeMessage message, TlsContext context) {
        HandshakeMessageHandler<HandshakeMessage> handler = message.getHandler(context);
        HandshakeMessageSerializer<HandshakeMessage> serializer = handler.getSerializer(message);
        byte[] bytes = serializer.serializeHandshakeMessageContent();
        List<DtlsHandshakeMessageFragment> fragments = generateFragments(message, bytes, bytes.length, context);
        return fragments.get(0);
    }

    private static List<DtlsHandshakeMessageFragment> generateFragments(HandshakeMessage message, byte[] handshakeBytes,
        int maxFragmentLength, TlsContext context) {
        List<DtlsHandshakeMessageFragment> fragments = new LinkedList<>();
        int currentOffset = 0;
        do {
            byte[] fragmentBytes = Arrays.copyOfRange(handshakeBytes, currentOffset,
                Math.min(currentOffset + maxFragmentLength, handshakeBytes.length));
            DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment(message.getHandshakeMessageType(),
                fragmentBytes, message.getMessageSequence().getValue(), currentOffset, handshakeBytes.length);
            SendMessageHelper.prepareMessage(fragment, context);
            fragments.add(fragment);
            currentOffset += maxFragmentLength;
        } while (currentOffset < handshakeBytes.length);

        return fragments;
    }

    private static List<DtlsHandshakeMessageFragment> generateFragments(HandshakeMessage message, byte[] handshakeBytes,
        List<DtlsHandshakeMessageFragment> fragments, TlsContext context) {
        int currentOffset = 0;
        for (DtlsHandshakeMessageFragment fragment : fragments) {
            Integer maxFragmentLength = fragment.getMaxFragmentLengthConfig();
            if (maxFragmentLength == null) {
                maxFragmentLength = context.getConfig().getDtlsMaximumFragmentLength();
            }
            byte[] fragmentBytes = Arrays.copyOfRange(handshakeBytes, currentOffset,
                Math.min(currentOffset + maxFragmentLength, handshakeBytes.length));
            fragment.setHandshakeMessageTypeConfig(message.getHandshakeMessageType());
            fragment.setFragmentContentConfig(fragmentBytes);
            fragment.setMessageSequenceConfig(message.getMessageSequence().getValue());
            fragment.setOffsetConfig(currentOffset);
            fragment.setHandshakeMessageLengthConfig(handshakeBytes.length);
            SendMessageHelper.prepareMessage(fragment, context);
            currentOffset += fragmentBytes.length;
        }

        return fragments;
    }
}
