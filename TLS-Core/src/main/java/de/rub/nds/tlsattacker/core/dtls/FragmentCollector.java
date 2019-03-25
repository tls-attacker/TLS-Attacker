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
import java.util.List;
import java.util.TreeSet;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.serializer.DtlsHandshakeMessageFragmentSerializer;

/**
 * Collector used for storing and assembling DTLS fragments. It provides support
 * for disorderly fragment insertion and fragment overlap.
 */
public class FragmentCollector {

    protected static final Logger LOGGER = LogManager.getLogger(FragmentCollector.class.getName());

    /**
     * The message length of fragments stored by the collector, as as determined
     * by the message length of the first fragment stored.
     */
    private Integer messageLength;

    /**
     * The message sequence of fragments stored by the collector, as as
     * determined by the message sequence of the first fragment stored.
     */
    private Integer messageSeq;

    /**
     * The type of fragments stored by the collector, as determined by the type
     * of the first fragment stored.
     */
    private Byte type;

    /**
     * A variable which configures the collector whether to store unfitting
     * fragments, that is, fragments whose message length, sequence or type
     * differs from those of the collector in case the collector is not empty.
     */
    private boolean onlyFitting;

    /**
     * A set which keeps fragments sorted firstly by their offset, secondly by
     * their length
     */
    private final TreeSet<DtlsHandshakeMessageFragment> fragmentData;

    public FragmentCollector(Config config) {
        fragmentData = new TreeSet<>(new Comparator<DtlsHandshakeMessageFragment>() {
            @Override
            public int compare(DtlsHandshakeMessageFragment o1, DtlsHandshakeMessageFragment o2) {
                int comp = o1.getFragmentOffset().getValue().compareTo(o2.getFragmentOffset().getValue());
                if (comp == 0) {
                    // if two fragments start at the same offset, we sort by
                    // length from longest to shortest
                    comp = o2.getFragmentLength().getValue().compareTo(o1.getFragmentLength().getValue());
                }
                return comp;
            }
        });
        this.onlyFitting = config.isDtlsOnlyFitting();
    }

    /**
     * Adds a fragment to the collection, unless the fragment is already
     * contained, or the fragment doesn't fit and
     * {@link FragmentCollector#onlyFitting} is set to true.
     * 
     * <p>
     * Fragments which "fit" share the same type, length and message sequence
     * with the first element inserted in the collection.
     * </p>
     * 
     * @return true if the fragment was added or false if it wasn't.
     */
    public boolean addFragment(DtlsHandshakeMessageFragment fragment) {
        if (type == null) {
            type = fragment.getType().getValue();
            messageSeq = fragment.getMessageSeq().getValue();
            messageLength = fragment.getLength().getValue();
        }

        boolean isFitting = isFitting(fragment);

        if (!fragmentData.contains(fragment) && (isFitting || !onlyFitting)) {
            fragmentData.add(fragment);
            return true;
        } else {
            return false;
        }
    }

    public boolean isFitting(DtlsHandshakeMessageFragment fragment) {
        if (type == null) {
            return true;
        } else {
            if (!fragment.getType().getValue().equals(type)) {
                LOGGER.warn("Found an unffiting fragment! Type before:" + type + " inserted fragment type:"
                        + fragment.getType().getValue());
                return false;
            } else if (!fragment.getMessageSeq().getValue().equals(messageSeq)) {
                LOGGER.warn("Found an unffiting fragment! Message seq before:" + messageSeq + " inserted message seq:"
                        + fragment.getMessageSeq().getValue());
                return false;
            } else if (!fragment.getLength().getValue().equals(messageLength)) {
                LOGGER.warn("Found an unffiting fragment! Message length before:" + messageLength
                        + " inserted fragment length:" + fragment.getLength().getValue());
                return false;
            }
            return true;
        }
    }

    /**
     * Assembles collected messages into a combined fragment. Note that missing
     * bytes are replaced by 0.
     */
    public DtlsHandshakeMessageFragment getCombinedFragment() {
        if (!isMessageComplete()) {
            LOGGER.warn("Returning incompletely received message! Missing pieces are replaced by 0 in content.");
        }
        if (type == null) {
            throw new WorkflowExecutionException("DtlsFragmentedMessage does not have type!");
        }

        DtlsHandshakeMessageFragment message = new DtlsHandshakeMessageFragment();
        message.setType(type);
        message.setLength(messageLength);
        message.setMessageSeq(messageSeq);
        message.setFragmentOffset(0);
        message.setFragmentLength(messageLength);
        message.setContent(getCombinedContent());
        DtlsHandshakeMessageFragmentSerializer serializer = new DtlsHandshakeMessageFragmentSerializer(message, null);
        message.setCompleteResultingMessage(serializer.serialize());
        return message;
    }

    /*
     * Combines the content in collected fragments, filling the gaps with 0s.
     * Note: the implementation relies on the sorted nature of {@link
     * fragmentData}.
     */
    private byte[] getCombinedContent() {
        try {
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            int currentOffset = 0;
            for (DtlsHandshakeMessageFragment fragment : fragmentData) {
                Integer fragOffset = fragment.getFragmentOffset().getValue();
                Integer fragLength = fragment.getFragmentLength().getValue();
                // fragment contains bytes already received
                if (currentOffset > fragOffset + fragLength) {
                    continue;
                } else {
                    // fragment starts at an offset we haven't yet arrived at
                    if (fragOffset > currentOffset) {
                        LOGGER.warn("Missing bytes between offsets " + fragOffset + " and " + currentOffset
                                + ". Filling gap with 0s.");
                        stream.write(new byte[fragOffset - currentOffset]);
                        currentOffset = fragOffset;
                    }
                    // the place to start copying
                    int offsetDiff = currentOffset - fragOffset;
                    stream.write(fragment.getContent().getValue(), offsetDiff, fragLength - offsetDiff);
                    currentOffset += (fragLength - offsetDiff);
                }
            }
            byte[] array = stream.toByteArray();
            if (!messageLength.equals(array.length)) {
                LOGGER.warn("Assembled message length is different than expected message length. "
                        + "Truncating/filling with 0s.");
                array = Arrays.copyOf(array, messageLength);
            }
            return array;
        } catch (IOException e) {
            LOGGER.error("Failure merging content, return 0 byte array", e);
            return new byte[messageLength];
        }
    }

    /**
     * Assembles the message, serializes it and returns the resulting byte
     * array.
     */
    public byte[] getCombinedFragmentAsByteArray() {
        DtlsHandshakeMessageFragment combinedFragment = getCombinedFragment();
        DtlsHandshakeMessageFragmentSerializer serializer = new DtlsHandshakeMessageFragmentSerializer(
                combinedFragment, null);
        return serializer.serialize();
    }

    /**
     * Returns true if enough messages have been received to assemble the
     * message. Otherwise returns false.
     */
    public boolean isMessageComplete() {
        if (messageLength == null) {
            return false;
        } else {
            int currentOffset = 0;
            for (DtlsHandshakeMessageFragment fragment : fragmentData) {
                if (currentOffset > fragment.getFragmentOffset().getValue() + fragment.getFragmentLength().getValue()) {
                    continue;
                } else {
                    if (fragment.getFragmentOffset().getValue() > currentOffset) {
                        return false;
                    } else {
                        currentOffset = fragment.getFragmentOffset().getValue()
                                + fragment.getFragmentLength().getValue();
                    }
                }
                if (currentOffset >= messageLength) {
                    break;
                }
            }

            if (currentOffset > messageLength) {
                LOGGER.warn("Assembled message is longer than message length");
            }

            return currentOffset >= messageLength;
        }
    }

}
