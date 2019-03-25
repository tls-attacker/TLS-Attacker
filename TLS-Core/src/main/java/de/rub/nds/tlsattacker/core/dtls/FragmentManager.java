/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.dtls;

import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;

/**
 * Manages multiple message fragment collectors. A user can add fragments, check
 * if the message corresponding to a fragment is complete, and construct the
 * message.
 *
 * @author Robert Merget <robert.merget@rub.de> Paul Fiterau
 *         <fiteraup@yahoo.com>
 */
public class FragmentManager {

    private static final Logger LOGGER = LogManager.getLogger(FragmentManager.class);

    private Map<Object, FragmentCollector> fragments;
    private Config config;

    public FragmentManager(Config config) {
        fragments = new HashMap<>();
        this.config = config;
    }

    public void addMessageFragment(DtlsHandshakeMessageFragment fragment) {
        FragmentCollector collector = fragments.get(messageSeq(fragment));
        if (collector == null) {
            collector = new FragmentCollector(config);
            fragments.put(messageSeq(fragment), collector);
        }
        collector.addFragment(fragment);
    }

    /**
     * Returns true if the message corresponding to this fragment is complete
     */
    public boolean isFragmentedMessageComplete(DtlsHandshakeMessageFragment fragment) {
        FragmentCollector collector = fragments.get(messageSeq(fragment));
        if (collector == null) {
            LOGGER.warn("Fragment belongs to foreign message, that is, "
                    + "message whose fragments haven't been added to the manager");
            return false;
        }
        return collector.isMessageComplete();
    }

    /**
     * Returns the fragmented message corresponding to this fragment as a single
     * combined fragment. Returns null if no message was stored for this
     * fragment, or if the fragmented message is incomplete.
     */
    public DtlsHandshakeMessageFragment getFragmentedMessage(DtlsHandshakeMessageFragment fragment) {
        FragmentCollector collector = fragments.get(messageSeq(fragment));
        if (collector == null || !collector.isMessageComplete()) {
            return null;
        }
        return collector.getCombinedFragment();
    }

    /**
     * Returns the stored fragmented message with the given messageSeq as as
     * single combined fragment. Returns null if no message was stored with this
     * message Seq, or if the message is incomplete.
     */
    public DtlsHandshakeMessageFragment getFragmentedMessage(Integer messageSeq) {
        FragmentCollector collector = fragments.get(messageSeq);
        if (collector == null || !collector.isMessageComplete()) {
            return null;
        }
        return collector.getCombinedFragment();
    }

    /**
     * Clears the fragmented message corresponding to this fragment.
     */
    public void clearFragmentedMessage(DtlsHandshakeMessageFragment fragment) {
        fragments.put(messageSeq(fragment), null);
    }

    /*
     * The message sequence is the key with which fragments are stored. It is
     * used to distinguish between fragments belonging to different messages.
     */
    private Object messageSeq(DtlsHandshakeMessageFragment fragment) {
        return fragment.getMessageSeq().getValue();
    }

}
