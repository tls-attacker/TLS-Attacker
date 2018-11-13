/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.dtls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Comparator;
import java.util.TreeSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.serializer.DtlsHandshakeMessageFragmentSerializer;

public class MessageFragmentCollector {

    protected static final Logger LOGGER = LogManager.getLogger(MessageFragmentCollector.class.getName());

    private Integer length;

    private Integer messageSeq;

    private Byte type;

    // a set which keeps fragments sorted by their offset
    private final TreeSet<DtlsHandshakeMessageFragment> fragmentData;

    public MessageFragmentCollector() {
        fragmentData = new TreeSet<>(new Comparator<DtlsHandshakeMessageFragment>() {
            @Override
            public int compare(DtlsHandshakeMessageFragment o1, DtlsHandshakeMessageFragment o2) {
                return o1.getFragmentOffset().getValue().compareTo(o2.getFragmentOffset().getValue());
            }
        });
    }

    public void insertFragment(DtlsHandshakeMessageFragment fragment) {
        parseType(fragment);
        parseMessageSeq(fragment);
        parseLength(fragment);
        if (!fragmentData.contains(fragment)) {
            fragmentData.add(fragment);
        }
    }

    private void parseType(DtlsHandshakeMessageFragment fragment) {
        Byte fType = fragment.getType().getValue();
        if (type == null) {
            type = fType;
        } else {
            if (!type.equals(fType)) {
                LOGGER.warn("Found an unffiting fragment! Type before:" + type + " inserted fragment type:" + fType);
            }
        }
    }

    private void parseMessageSeq(DtlsHandshakeMessageFragment fragment) {
        Integer fMessageSeq = fragment.getMessageSeq().getValue();
        if (messageSeq == null) {
            messageSeq = fMessageSeq;
        } else {
            if (!messageSeq.equals(fMessageSeq)) {
                LOGGER.warn("Found an unffiting fragment! Message seq before:" + messageSeq
                        + " inserted fragment message seq:" + fMessageSeq);
            }
        }
    }

    private void parseLength(DtlsHandshakeMessageFragment fragment) {
        Integer fLength = fragment.getLength().getValue();
        if (length == null) {
            length = fLength;
        } else {
            if (!length.equals(fLength)) {
                LOGGER.warn("Found an unffiting fragment! Message length before:" + length
                        + " inserted fragment length:" + fLength);
            }
        }
    }

    public DtlsHandshakeMessageFragment getCombinedFragment() {
        if (!isMessageComplete()) {
            LOGGER.warn("Returning incompletly received message! Missing pieces are replaced by 0 in content.");
        }
        if (type == null) {
            throw new WorkflowExecutionException("DtlsFragmentedMessage does not have type!");
        }

        DtlsHandshakeMessageFragment message = new DtlsHandshakeMessageFragment();
        message.setType(type);
        message.setLength(length);
        message.setMessageSeq(messageSeq);
        message.setFragmentOffset(0);
        message.setFragmentLength(length);
        message.setContent(getCombinedContent());
        return message;
    }

    /*
     * TODO: take into account offset when building the combined content (then
     * we may no longer need TreeSets) also, there are no inconsistency checks
     */
    private byte[] getCombinedContent() {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            for (DtlsHandshakeMessageFragment fragment : fragmentData) {
                stream.write(fragment.getContent().getValue());
            }
            byte[] array = stream.toByteArray();
            if (!length.equals(array.length)) {
                LOGGER.warn("Received message content is of length other than message length, "
                        + "truncating/filling with 0 to message length");
                array = Arrays.copyOf(array, length);
            }
            return array;
        } catch (IOException e) {
            LOGGER.error("Failure merging content, return false byte array");
            return new byte[length];
        }
    }

    public byte[] getFragmentedMessageAsByteArray() {
        DtlsHandshakeMessageFragment combinedFragment = getCombinedFragment();
        DtlsHandshakeMessageFragmentSerializer serializer = new DtlsHandshakeMessageFragmentSerializer(
                combinedFragment, null);
        return serializer.serialize();
    }

    public boolean isMessageComplete() {
        if (length == null) {
            return false;
        } else {
            // this part is screaming for Java 8 Lambdas
            int combinedLength = 0;
            for (DtlsHandshakeMessageFragment fragment : fragmentData) {
                combinedLength += fragment.getFragmentLength().getValue();
            }
            return combinedLength == length;
        }
    }

}
