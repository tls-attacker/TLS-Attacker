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
    private Map<Object, FragmentCollector> fragments;

    private static final Logger LOGGER = LogManager.getLogger(FragmentManager.class);

    public FragmentManager() {
        fragments = new HashMap<>();
    }

    public void addMessageFragment(DtlsHandshakeMessageFragment fragment) {
        FragmentCollector collector = fragments.get(key(fragment));
        if (collector == null) {
            collector = new FragmentCollector();
            fragments.put(key(fragment), collector);
        }
        collector.insertFragment(fragment);
    }

    /**
     * Returns true if the message corresponding to this fragment is complete
     */
    public boolean isFragmentedMessageComplete(DtlsHandshakeMessageFragment fragment) {
        FragmentCollector collector = fragments.get(key(fragment));
        if (collector == null) {
        	LOGGER.warn("Fragment belongs to foreign message, that is, "
        			+ "message whose fragments haven't been added to the manager");
        	return false;
        }
        return collector.isMessageComplete();
    }

    /**
     * Returns the byte array of the message corresponding to this fragment
     */
    public byte[] getFragmentedMessageAsByteArray(DtlsHandshakeMessageFragment fragment) {
        FragmentCollector collector = fragments.get(key(fragment));
        if (!collector.isMessageComplete()) {
            LOGGER.warn("Message is incomplete");
        }
        byte[] fragmentedMessageBytes = collector.getCombinedFragmentAsByteArray();
        return fragmentedMessageBytes;
    }

    /**
     * Clears the fragmented message corresponding to this fragment.
     */
    public void clearFragmentedMessage(DtlsHandshakeMessageFragment fragment) {
        fragments.put(key(fragment), null);
    }

    /*
     * The key of a fragment is the message sequence. The key is used to distinguish between
     * fragments belonging to different messages.
     */
    private Object key(DtlsHandshakeMessageFragment fragment) {
        return fragment.getMessageSeq().getValue();
    }

}
