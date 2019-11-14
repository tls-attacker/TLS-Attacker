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
import de.rub.nds.tlsattacker.core.exceptions.IllegalDtlsFragmentException;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.serializer.DtlsHandshakeMessageFragmentSerializer;
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

    private boolean interpreted = false;

    private final Config config;

    private FragmentStream fragmentStream;

    public FragmentCollector(Config config, Byte type, int messageSeq, int messageLength) {
        this.config = config;
        fragmentStream = new FragmentStream(messageLength);
        this.type = type;
        this.messageLength = messageLength;
        this.messageSeq = messageSeq;
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
    public void addFragment(DtlsHandshakeMessageFragment fragment) {
        if (wouldAdd(fragment)) {
            if (isFragmentOverwritingContent(fragment)) {
                LOGGER.warn("Found a fragment which tries to rewrite history. Setting interpreted to false and resetting Stream.");
                fragmentStream = new FragmentStream(messageLength);
                this.messageLength = fragment.getLength().getValue();
                this.messageSeq = fragment.getMessageSeq().getValue();
                this.type = fragment.getType().getValue();
                interpreted = false;
            }
            fragmentStream.insertByteArray(fragment.getContent().getValue(), fragment.getFragmentOffset().getValue());
        } else {
            throw new IllegalDtlsFragmentException("Tried to insert an illegal DTLS fragment.");
        }
    }

    public boolean wouldAdd(DtlsHandshakeMessageFragment fragment) {
        if (config.isAcceptContentRewritingDtlsFragments() || !isFragmentOverwritingContent(fragment)) {
            if (!config.isAcceptOnlyFittingDtlsFragments() || isFitting(fragment)) {
                return true;
            } else {
                LOGGER.warn("Would not add not fitting fragment");
                return false;
            }
        } else {
            LOGGER.warn("Received history rewriting fragment");
            return false;
        }
    }

    /**
     * Returns true for fragments which "fit" the collector, that is they share
     * the type, length and message sequence with the first fragment added to
     * the collector.
     *
     * @param fragment
     * @return true if fragment fits the collector, false if it doesn't
     */
    public boolean isFitting(DtlsHandshakeMessageFragment fragment) {
        if (fragment.getType().getValue() == type && fragment.getMessageSeq().getValue() == this.messageSeq
                && fragment.getLength().getValue() == this.messageLength) {
            return fragmentStream.canInsertByteArray(fragment.getContent().getValue(), fragment.getFragmentOffset()
                    .getValue());
        } else {
            return false;
        }
    }

    public boolean isFragmentOverwritingContent(DtlsHandshakeMessageFragment fragment) {
        return !fragmentStream.canInsertByteArray(fragment.getContent().getValue(), fragment.getFragmentOffset()
                .getValue());
    }

    /**
     * Assembles collected fragments into a combined fragment. Note that missing
     * bytes are replaced by 0. Throws an exception if the collector
     * {@link #isEmpty()}.
     */
    public DtlsHandshakeMessageFragment buildCombinedFragment() {
        if (!isMessageComplete()) {
            LOGGER.warn("Returning incompletely received message! Missing pieces are ignored in the content.");
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
        this.setInterpreted(interpreted);
        return message;
    }

    /*
     * Combines the content in collected fragments, filling the gaps with 0s.
     * Note: the implementation relies on the sorted nature of {@link
     * fragmentData}.
     */
    private byte[] getCombinedContent() {
        return fragmentStream.getCompleteTruncatedStream();
    }

    /**
     * Returns true if enough messages have been received to assemble the
     * message. Otherwise returns false.
     */
    public boolean isMessageComplete() {
        return fragmentStream.isComplete(messageLength);
    }

    public boolean isInterpreted() {
        return interpreted;
    }

    public void setInterpreted(boolean interpreted) {
        this.interpreted = interpreted;
    }
}
