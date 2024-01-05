/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls;

import static de.rub.nds.tlsattacker.core.dtls.FragmentUtils.fragment;
import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class FragmentManagerTest {

    private FragmentManager manager;

    @BeforeEach
    public void setUp() {
        manager = new FragmentManager(Config.createConfig());
    }

    @Test
    public void testIsMessageCompleteTrue() {
        manager.addMessageFragment(fragment(0, 0, 5, 0));
        manager.addMessageFragment(fragment(0, 5, 5, 0));
        assertTrue(manager.isFragmentedMessageComplete(0, 0));
    }

    @Test
    public void testIsMessageCompleteFalse() {
        manager.addMessageFragment(fragment(0, 0, 5, 0));
        manager.addMessageFragment(fragment(0, 6, 5, 0));
        assertFalse(manager.isFragmentedMessageComplete(0, 0));
    }

    @Test
    public void testIsMessageCompleteFalseDifferentEpochs() {
        manager.addMessageFragment(fragment(0, 0, 5, 0));
        manager.addMessageFragment(fragment(0, 5, 5, 1));
        assertFalse(manager.isFragmentedMessageComplete(0, 0));
    }

    @Test
    public void testIsMessageCompleteFalseEmpty() {
        assertFalse(manager.isFragmentedMessageComplete(0, 0));
    }

    @Test
    public void testClearFragmentedMessage() {
        manager.addMessageFragment(fragment(0, 0, 5, 0));
        manager.addMessageFragment(fragment(0, 5, 5, 0));
        manager.clearFragmentedMessage(0, 0);
        assertFalse(manager.isFragmentedMessageComplete(0, 0));
        assertNull(manager.getCombinedMessageFragment(0, 0));
    }

    @Test
    public void testGetFragmentedMessageMultipleMessages() {
        manager.addMessageFragment(fragment(0, 0, 5, new byte[] {0, 1, 2, 3, 4}, 0));
        manager.addMessageFragment(fragment(1, 0, 5, new byte[] {8, 9, 10, 11, 12}, 0));
        manager.addMessageFragment(fragment(0, 5, 5, new byte[] {5, 6, 7, 8, 9}, 0));
        manager.addMessageFragment(fragment(0, 0, 2, new byte[] {9, 8}, 1));
        manager.addMessageFragment(fragment(0, 2, 8, new byte[] {7, 6, 5, 4, 3, 2, 1, 0}, 1));
        assertNull(manager.getCombinedMessageFragment(1, 0));
        DtlsHandshakeMessageFragment fragmentedMessageEpoch0 =
                manager.getCombinedMessageFragment(0, 0);
        FragmentUtils.assertFragment(
                fragmentedMessageEpoch0, 0, 10, new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
        DtlsHandshakeMessageFragment fragmentedMessageEpoch1 =
                manager.getCombinedMessageFragment(0, 1);
        FragmentUtils.assertFragment(
                fragmentedMessageEpoch1, 0, 10, new byte[] {9, 8, 7, 6, 5, 4, 3, 2, 1, 0});
    }

    @Test
    public void testGetFragmentedMessageDisordelyOverlapping() {
        manager.addMessageFragment(fragment(0, 0, 5, new byte[] {0, 1, 2, 3, 4}, 0));
        manager.addMessageFragment(fragment(0, 7, 3, new byte[] {7, 8, 9}, 0));
        manager.addMessageFragment(fragment(0, 5, 4, new byte[] {5, 6, 7, 8}, 0));
        manager.addMessageFragment(fragment(0, 0, 5, new byte[] {0, 1, 2, 3, 4}, 0));
        DtlsHandshakeMessageFragment fragmentedMessage = manager.getCombinedMessageFragment(0, 0);
        FragmentUtils.assertFragment(
                fragmentedMessage, 0, 10, new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
    }
}
