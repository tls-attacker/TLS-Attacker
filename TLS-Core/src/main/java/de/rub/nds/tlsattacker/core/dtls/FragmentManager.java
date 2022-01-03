/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Manages multiple message fragment collectors. A user can add fragments, check if the message corresponding to a
 * fragment is complete, and construct the message.
 */
public class FragmentManager {

    private static final Logger LOGGER = LogManager.getLogger();

    private Map<FragmentKey, FragmentCollector> fragments;
    private Config config;
    private int lastInterpretedMessageSeq = -1;

    public FragmentManager(Config config) {
        fragments = new HashMap<>();
        this.config = config;
    }

    public boolean addMessageFragment(DtlsHandshakeMessageFragment fragment) {
        FragmentKey key = new FragmentKey(fragment.getMessageSeq().getValue(), fragment.getEpoch().getValue());
        FragmentCollector collector = fragments.get(key);
        if (collector == null) {
            collector = new FragmentCollector(config, fragment.getType().getValue(),
                fragment.getMessageSeq().getValue(), fragment.getLength().getValue());
            fragments.put(key, collector);
        }
        if (collector.wouldAdd(fragment)) {
            collector.addFragment(fragment);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Returns true if the message corresponding to this messageSeq and epoch is complete, returns false otherwise.
     */
    public boolean isFragmentedMessageComplete(Integer messageSeq, Integer epoch) {
        FragmentKey key = new FragmentKey(messageSeq, epoch);
        FragmentCollector collector = fragments.get(key);
        if (collector == null) {
            return false;
        }
        return collector.isMessageComplete();
    }

    public List<DtlsHandshakeMessageFragment> getOrderedCombinedUninterpretedMessageFragments(boolean onlyIfComplete,
        boolean skipMessageSequences) {
        List<DtlsHandshakeMessageFragment> handshakeFragmentList = new LinkedList<>();
        List<FragmentKey> orderedFragmentKeys = new ArrayList<>(fragments.keySet());
        orderedFragmentKeys.sort(new Comparator<FragmentKey>() {
            @Override
            public int compare(FragmentKey fragmentKey1, FragmentKey fragmentKey2) {
                if (fragmentKey1.getEpoch() > fragmentKey2.getEpoch()) {
                    return -1;
                } else if (fragmentKey1.getEpoch() < fragmentKey2.getEpoch()) {
                    return 1;
                } else {
                    return fragmentKey1.getMessageSeq().compareTo(fragmentKey2.getMessageSeq());
                }
            }
        });

        for (FragmentKey key : orderedFragmentKeys) {
            FragmentCollector fragmentCollector = fragments.get(key);
            if (fragmentCollector == null) {
                LOGGER.error("Trying to access unreceived message fragment. Not processing: msg_sqn: "
                    + key.getMessageSeq() + " epoch: " + key.getEpoch());
                if (!skipMessageSequences) {
                    break;
                } else {
                    continue;
                }
            }
            if (!fragmentCollector.isInterpreted()) {
                if (!skipMessageSequences && key.getMessageSeq() != lastInterpretedMessageSeq + 1
                    && !fragmentCollector.isRetransmission()) {
                    break;
                }
                if (onlyIfComplete && !fragmentCollector.isMessageComplete()) {
                    LOGGER.debug("Incomplete message. Not processing: msg_sqn: " + key.getMessageSeq() + " epoch: "
                        + key.getEpoch());
                } else {
                    handshakeFragmentList.add(fragmentCollector.buildCombinedFragment());
                    fragmentCollector.setInterpreted(true);
                    lastInterpretedMessageSeq = key.getMessageSeq();
                }
            }
        }
        return handshakeFragmentList;
    }

    public boolean areAllMessageFragmentsComplete() {
        for (FragmentCollector collector : fragments.values()) {
            if (!collector.isMessageComplete()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Returns the stored fragmented message with the given messageSeq and epoch, as a single combined fragment. Returns
     * null if no message was stored with this messageSeq, or if the message is incomplete.
     * 
     * @param  messageSeq
     * @param  epoch
     * @return
     */
    public DtlsHandshakeMessageFragment getCombinedMessageFragment(Integer messageSeq, Integer epoch) {
        FragmentKey key = new FragmentKey(messageSeq, epoch);
        FragmentCollector collector = fragments.get(key);
        if (collector == null) {
            LOGGER.warn("Trying to access not received handshake fragment.");
            return null;
        } else if (!collector.isMessageComplete()) {
            LOGGER.warn("Did not receive all fragments for msq_sqn:" + messageSeq + " epoch: " + epoch);
            return null;
        }
        return collector.buildCombinedFragment();
    }

    /**
     * Clears the fragmented message corresponding to this messageSeq and epoch.
     */
    public void clearFragmentedMessage(Integer messageSeq, Integer epoch) {
        FragmentKey key = new FragmentKey(messageSeq, epoch);
        fragments.remove(key);
    }

}
