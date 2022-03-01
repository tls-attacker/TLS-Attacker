/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

import static de.rub.nds.tlsattacker.core.dtls.FragmentCollector.LOGGER;
import de.rub.nds.tlsattacker.core.exceptions.AdjustmentException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.*;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.util.Arrays;

/**
 * Class used to split HandshakeMessages into DTLS fragments.
 */
public class MessageFragmenter {

    /**
     * Takes a message and splits it into prepared fragments.
     *
     * @param  message
     * @param  tlsContext
     * @return
     */
    public static List<DtlsHandshakeMessageFragment> fragmentMessage(HandshakeMessage message, int maxFragmentLength,
        TlsContext tlsContext) {
        byte[] bytes = getSerializedBytes(message, tlsContext);
        List<DtlsHandshakeMessageFragment> dtlsFragments =
            generateFragments(message, bytes, maxFragmentLength, tlsContext);
        return dtlsFragments;
    }

    /**
     * Takes a message and splits it into prepared fragments.
     */
    public static List<DtlsHandshakeMessageFragment> fragmentMessage(HandshakeMessage message,
        List<DtlsHandshakeMessageFragment> fragments, TlsContext tlsContext) {
        byte[] bytes = getSerializedBytes(message, tlsContext);
        List<DtlsHandshakeMessageFragment> dtlsFragments = generateFragments(message, bytes, fragments, tlsContext);
        return dtlsFragments;
    }

    private static byte[] getSerializedBytes(HandshakeMessage message, TlsContext tlsContext) {
        HandshakeMessageSerializer serializer = message.getSerializer(tlsContext);
        byte[] bytes;
        bytes = serializer.serializeProtocolMessageContent();
        return bytes;
    }

    /**
     * Generates a single fragment carrying the contents of the message as payload.
     *
     * @param  message
     * @param  tlsContext
     * @return
     */
    public static DtlsHandshakeMessageFragment wrapInSingleFragment(HandshakeMessage message, TlsContext tlsContext) {
        byte[] bytes = getSerializedBytes(message, tlsContext);
        List<DtlsHandshakeMessageFragment> fragments = generateFragments(message, bytes, bytes.length, tlsContext);
        return fragments.get(0);
    }

    private static List<DtlsHandshakeMessageFragment> generateFragments(HandshakeMessage message, byte[] handshakeBytes,
        int maxFragmentLength, TlsContext tlsContext) {
        List<DtlsHandshakeMessageFragment> fragments = new LinkedList<>();
        int currentOffset = 0;
        do {
            byte[] fragmentBytes = Arrays.copyOfRange(handshakeBytes, currentOffset,
                Math.min(currentOffset + maxFragmentLength, handshakeBytes.length));
            int sequence;
            if (message.getMessageSequence() != null) {
                sequence = message.getMessageSequence().getValue();
            } else {
                // it is possible that not all messages are created under a DTLS tlsContext such that they do not have a
                // message sequence
                sequence = 0;
            }
            DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment(message.getHandshakeMessageType(),
                fragmentBytes, sequence, currentOffset, handshakeBytes.length);
            fragment.getPreparator(tlsContext).prepare();
            fragments.add(fragment);
            currentOffset += maxFragmentLength;
        } while (currentOffset < handshakeBytes.length);

        return fragments;
    }

    public static byte[] prepareMessage(ProtocolMessage message, boolean withPrepare, TlsContext tlsContext) {
        if (withPrepare) {
            Preparator<ProtocolMessage> preparator = message.getPreparator(tlsContext);
            preparator.prepare();
            preparator.afterPrepare();
            Serializer<ProtocolMessage> serializer = message.getSerializer(tlsContext);
            byte[] completeMessage = serializer.serialize();
            message.setCompleteResultingMessage(completeMessage);
        }
        try {
            if (message.getAdjustContext()) {
                if (tlsContext.getConfig().getDefaultSelectedProtocolVersion().isDTLS()
                    && (message instanceof HandshakeMessage)
                    && !((HandshakeMessage) message).isDtlsHandshakeMessageFragment()) {
                    tlsContext.increaseDtlsWriteHandshakeMessageSequence();
                }
            }

            ProtocolMessageHandler handler = message.getHandler(tlsContext);
            handler.updateDigest(message);
            if (message.getAdjustContext()) {

                message.getHandler(tlsContext).adjustContext(message);
            }
        } catch (AdjustmentException e) {
            LOGGER.warn("Could not adjust TLSContext");
            LOGGER.debug(e);
        }

        return message.getCompleteResultingMessage().getValue();
    }

    private static List<DtlsHandshakeMessageFragment> generateFragments(HandshakeMessage message, byte[] handshakeBytes,
        List<DtlsHandshakeMessageFragment> fragments, TlsContext tlsContext) {
        int currentOffset = 0;
        for (DtlsHandshakeMessageFragment fragment : fragments) {
            Integer maxFragmentLength = fragment.getMaxFragmentLengthConfig();
            if (maxFragmentLength == null) {
                maxFragmentLength = tlsContext.getConfig().getDtlsMaximumFragmentLength();
            }
            byte[] fragmentBytes = Arrays.copyOfRange(handshakeBytes, currentOffset,
                Math.min(currentOffset + maxFragmentLength, handshakeBytes.length));
            fragment.setHandshakeMessageTypeConfig(message.getHandshakeMessageType());
            fragment.setFragmentContentConfig(fragmentBytes);
            int sequence;
            if (message.getMessageSequence() != null) {
                sequence = message.getMessageSequence().getValue();
            } else {
                // it is possible that not all messages are created under a DTLS tlsContext such that they do not have a
                // message sequence
                sequence = 0;
            }
            fragment.setMessageSequenceConfig(sequence);
            fragment.setOffsetConfig(currentOffset);
            fragment.setHandshakeMessageLengthConfig(handshakeBytes.length);
            prepareMessage(message, true, tlsContext);
            currentOffset += fragmentBytes.length;
        }

        return fragments;
    }
}
