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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Manages multiple message fragment collectors. A user can add fragments, check
 * if the message corresponding to a fragment is complete, and construct the
 * message.
 */
public class FragmentManager {

    private static final Logger LOGGER = LogManager.getLogger(FragmentManager.class);

    private Map<FragmentKey, FragmentCollector> fragments;
    private Config config;

    public FragmentManager(Config config) {
        fragments = new HashMap<>();
        this.config = config;
    }

    /**
     * Adds a fragment to the collector corresponding to the fragment's
     * messageSeq and the given epoch. Instantiates a new collector if no
     * collector exists.
     * 
     * @return true if the fragment was added successfully, or false if it was
     *         rejected by the collector.
     */
    public boolean addMessageFragment(DtlsHandshakeMessageFragment fragment, Integer epoch) {
        FragmentKey key = new FragmentKey(fragment.getMessageSeq().getValue(), epoch);
        FragmentCollector collector = fragments.get(key);
        if (collector == null) {
            collector = new FragmentCollector(config);
            fragments.put(key, collector);
        }
        return collector.addFragment(fragment);
    }

    /**
     * Returns true if the message corresponding to this messageSeq and epoch is
     * complete, returns false otherwise.
     */
    public boolean isFragmentedMessageComplete(Integer messageSeq, Integer epoch) {
        FragmentKey key = new FragmentKey(messageSeq, epoch);
        FragmentCollector collector = fragments.get(key);
        if (collector == null) {
            return false;
        }
        return collector.isMessageComplete();
    }

    /**
     * Returns the stored fragmented message with the given messageSeq and
     * epoch, as a single combined fragment. Returns null if no message was
     * stored with this messageSeq, or if the message is incomplete.
     */
    public DtlsHandshakeMessageFragment getFragmentedMessage(Integer messageSeq, Integer epoch) {
        FragmentKey key = new FragmentKey(messageSeq, epoch);
        FragmentCollector collector = fragments.get(key);
        if (collector == null || !collector.isMessageComplete()) {
            return null;
        }
        return collector.buildCombinedFragment();
    }

    /**
     * Returns the stored fragments for the given messageSeq and epoch.
     */
    public List<DtlsHandshakeMessageFragment> getStoredFragments(Integer messageSeq, Integer epoch) {
        FragmentKey key = new FragmentKey(messageSeq, epoch);
        FragmentCollector collector = fragments.get(key);
        if (collector == null) {
            return new ArrayList<>();
        }
        return collector.getStoredFragments();
    }

    /**
     * Clears the fragmented message corresponding to this messageSeq and epoch.
     */
    public void clearFragmentedMessage(Integer messageSeq, Integer epoch) {
        FragmentKey key = new FragmentKey(messageSeq, epoch);
        fragments.remove(key);
    }

    static class FragmentKey {
        private Integer messageSeq;
        private Integer epoch;

        public FragmentKey(Integer messageSeq, Integer epoch) {
            super();
            this.messageSeq = messageSeq;
            this.epoch = epoch;
        }

        public Integer getEpoch() {
            return epoch;
        }

        public Integer getMessageSeq() {
            return messageSeq;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((epoch == null) ? 0 : epoch.hashCode());
            result = prime * result + ((messageSeq == null) ? 0 : messageSeq.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            FragmentKey other = (FragmentKey) obj;
            if (epoch == null) {
                if (other.epoch != null)
                    return false;
            } else if (!epoch.equals(other.epoch))
                return false;
            if (messageSeq == null) {
                if (other.messageSeq != null)
                    return false;
            } else if (!messageSeq.equals(other.messageSeq))
                return false;
            return true;
        }

        public String toString() {
            return String.format("Key{messageSeq:%d,epoch:%d}", messageSeq, epoch);
        }

    }
}
