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
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.serializer.DtlsHandshakeMessageFragmentSerializer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
        onlyFitting = config.isDtlsOnlyFitting();
    }

    /**
     * Adds a fragment to the collection, unless the fragment is already
     * contained, or the fragment doesn't fit and
     * {@link FragmentCollector#onlyFitting} is set to true. In case the
     * collector is empty, also updates the "type" (given by type, message
     * sequence, message length) of the collector with that of the fragment.
     * 
     * @return true if the fragment was added or false if it wasn't.
     */
    // TODO perhaps it would make sense to extract this "type" to a separate
    // internal class?
    // instance of this class could be then extracted from the collector and
    // from the fragment
    public boolean addFragment(DtlsHandshakeMessageFragment fragment) {
        // this is the invariant of the collector
        assert (messageLength == null && type == null && messageSeq == null && fragmentData.isEmpty())
                || (messageLength != null && type != null && messageSeq != null && !fragmentData.isEmpty());
        if (isEmpty()) {
            type = fragment.getType().getValue();
            messageSeq = fragment.getMessageSeq().getValue();
            messageLength = fragment.getLength().getValue();
        }

        boolean isFitting = isFitting(fragment);

        if (!fragmentData.contains(fragment) && (isFitting || !onlyFitting)) {
            if (!isFitting) {
                LOGGER.warn(String.format("Adding an unffiting fragment! \n"
                        + "(type, message sequence, message length) of collector is "
                        + "(%s,%s,%s)\n and of added fragment is (%s,%s%s)", type, messageSeq, messageLength, fragment
                        .getType().getValue(), fragment.getMessageSeq().getValue(), fragment.getLength().getValue()));
            }
            fragmentData.add(fragment);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns true for fragments which "fit" the collector, that is they share
     * the type, length and message sequence with the first fragment added to
     * the collector. Fragments also fit if the collector is empty.
     * 
     * @param fragment
     * @return true if fragment fits the collector, false if it doesn't
     */
    public boolean isFitting(DtlsHandshakeMessageFragment fragment) {
        if (fragmentData.isEmpty()) {
            return true;
        } else {
            return fragment.getType().getValue().equals(type) && fragment.getMessageSeq().getValue().equals(messageSeq)
                    && fragment.getLength().getValue().equals(messageLength);
        }
    }

    /**
     * Returns a list with stored fragments.
     */
    public List<DtlsHandshakeMessageFragment> getStoredFragments() {
        return new ArrayList<>(fragmentData);
    }

    /**
     * Assembles collected fragments into a combined fragment. Note that missing
     * bytes are replaced by 0. Throws an exception if the collector
     * {@link #isEmpty()}.
     */
    public DtlsHandshakeMessageFragment buildCombinedFragment() {
        if (!isMessageComplete()) {
            LOGGER.warn("Returning incompletely received message! Missing pieces are replaced by 0 in content.");
        }
        if (isEmpty()) {
            throw new WorkflowExecutionException("The FragmentCollector is empty, cannot build combined fragment!");
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
                        + "Truncating/Filling with 0s.");
                array = Arrays.copyOf(array, messageLength);
            }
            return array;
        } catch (IOException e) {
            LOGGER.error("Failure merging content, return 0 byte array", e);
            return new byte[messageLength];
        }
    }

    /**
     * Returns true if no fragments have been added, false otherwise.
     */
    public boolean isEmpty() {
        return fragmentData.isEmpty();
    }

    /**
     * Returns true if enough messages have been received to assemble the
     * message. Otherwise returns false.
     */
    public boolean isMessageComplete() {
        if (isEmpty()) {
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
