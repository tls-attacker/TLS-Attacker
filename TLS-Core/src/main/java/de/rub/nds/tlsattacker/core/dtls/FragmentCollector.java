/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.IllegalDtlsFragmentException;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.serializer.DtlsHandshakeMessageFragmentSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Collector used for storing and assembling DTLS fragments. It provides support for disorderly
 * fragment insertion and fragment overlap.
 */
public class FragmentCollector {

    protected static final Logger LOGGER = LogManager.getLogger();

    private Integer messageLength;

    private Integer messageSeq;

    private Byte type;

    private boolean interpreted = false;

    private boolean retransmission = false;

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
     * Adds a fragment into the fragmentStream. If the would not be added an
     * IllegalDtlsFragmentException is thrown. This can for example be the case if the fragment is
     * not fitting into the data stream. If a fragment would be added but is rewriting previous
     * messages in the stream, these messages are marked as not interpreted. and the parameters of
     * the fragmentCollector are rewritten.
     */
    public void addFragment(DtlsHandshakeMessageFragment fragment) {
        if (wouldAdd(fragment)) {
            if (isFragmentOverwritingContent(fragment)) {
                LOGGER.warn(
                        "Found a fragment which tries to rewrite history. Setting interpreted to false and resetting Stream.");
                fragmentStream = new FragmentStream(fragment.getLength().getValue());
                this.messageLength = fragment.getLength().getValue();
                this.messageSeq = fragment.getMessageSequence().getValue();
                this.type = fragment.getType().getValue();
                interpreted = false;
                retransmission = false;
            }
            if (interpreted && config.isAddRetransmissionsToWorkflowTraceInDtls()) {
                fragmentStream = new FragmentStream(fragment.getLength().getValue());
                this.messageLength = fragment.getLength().getValue();
                this.messageSeq = fragment.getMessageSequence().getValue();
                this.type = fragment.getType().getValue();
                interpreted = false;
                retransmission = true;
            }
            fragmentStream.insertByteArray(
                    fragment.getMessageContent().getValue(),
                    fragment.getFragmentOffset().getValue());
        } else {
            throw new IllegalDtlsFragmentException("Tried to insert an illegal DTLS fragment.");
        }
    }

    /**
     * Tests if a Fragment would be added into the fragmentStream. The test depends on config flags
     * and if the fragment is fitting into the stream.
     *
     * @param fragment the fragment that should be tested.
     * @return True if it would be added, false otherwise
     */
    public boolean wouldAdd(DtlsHandshakeMessageFragment fragment) {
        if (config.isAcceptContentRewritingDtlsFragments()
                || !isFragmentOverwritingContent(fragment)) {
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
     * Returns true for fragments which "fit" the collector, that is they share the type, length and
     * message sequence with the first fragment added to the collector.
     *
     * @param fragment
     * @return true if fragment fits the collector, false if it doesn't
     */
    public boolean isFitting(DtlsHandshakeMessageFragment fragment) {
        if (fragment.getType().getValue() == type
                && fragment.getMessageSequence().getValue() == this.messageSeq
                && fragment.getLength().getValue() == this.messageLength) {
            return fragmentStream.canInsertByteArray(
                    fragment.getMessageContent().getValue(),
                    fragment.getFragmentOffset().getValue());
        } else {
            return false;
        }
    }

    /**
     * Tests if the fragment if added to the fragmentStream would rewrite previously received
     * messages
     *
     * @param fragment Fragment that should be tested
     * @return True if the fragment would overwrite paste messages
     */
    public boolean isFragmentOverwritingContent(DtlsHandshakeMessageFragment fragment) {
        return !fragmentStream.canInsertByteArray(
                fragment.getMessageContent().getValue(), fragment.getFragmentOffset().getValue());
    }

    /**
     * Assembles collected fragments into a combined fragment. Note that missing bytes are replaced
     * by 0.
     */
    public DtlsHandshakeMessageFragment buildCombinedFragment() {
        if (!isMessageComplete()) {
            LOGGER.warn(
                    "Returning incompletely received message! Missing pieces are ignored in the content.");
        }

        DtlsHandshakeMessageFragment message = new DtlsHandshakeMessageFragment();
        message.setType(type);
        message.setLength(messageLength);
        message.setMessageSequence(messageSeq);
        message.setFragmentOffset(0);
        message.setFragmentLength(messageLength);
        message.setMessageContent(getCombinedContent());
        DtlsHandshakeMessageFragmentSerializer serializer =
                new DtlsHandshakeMessageFragmentSerializer(message);
        message.setCompleteResultingMessage(serializer.serialize());
        message.setRetransmission(retransmission);
        message.setIncludeInDigest(!retransmission);
        interpreted = true;
        return message;
    }

    /*
     * Combines the content in collected fragments, filling the gaps with 0s. Note: the implementation relies on the
     * sorted nature of {@link fragmentData}.
     */
    private byte[] getCombinedContent() {
        return fragmentStream.getCompleteTruncatedStream();
    }

    /**
     * Returns true if enough messages have been received to assemble the message. Otherwise returns
     * false.
     */
    public boolean isMessageComplete() {
        return fragmentStream.isComplete(messageLength);
    }

    /**
     * Returns true if the message from this fragment stream has already been handled by the calling
     * layer
     *
     * @return
     */
    public boolean isInterpreted() {
        return interpreted;
    }

    /**
     * Marks this message as already handled by the calling layer
     *
     * @param interpreted
     */
    public void setInterpreted(boolean interpreted) {
        this.interpreted = interpreted;
    }

    /**
     * Returns true if the message from this fragment stream is a retransmission
     *
     * @return
     */
    public boolean isRetransmission() {
        return retransmission;
    }

    /**
     * Marks this message as retransmission
     *
     * @param retransmission
     */
    public void setRetransmission(boolean retransmission) {
        this.retransmission = retransmission;
    }
}
