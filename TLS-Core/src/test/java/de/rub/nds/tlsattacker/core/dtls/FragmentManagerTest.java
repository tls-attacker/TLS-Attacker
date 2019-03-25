/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.dtls;

import static de.rub.nds.tlsattacker.core.dtls.FragmentUtils.fragment;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;

public class FragmentManagerTest {

    private FragmentManager manager;

    @Before
    public void setUp() {
        manager = new FragmentManager(Config.createConfig());
    }

    @Test
    public void testIsMessageCompleteTrue() {
        DtlsHandshakeMessageFragment frag = fragment(0, 0, 5);
        manager.addMessageFragment(frag);
        manager.addMessageFragment(fragment(0, 5, 5));
        assertTrue(manager.isFragmentedMessageComplete(frag));
    }

    @Test
    public void testIsMessageCompleteFalse() {
        DtlsHandshakeMessageFragment frag = fragment(0, 0, 5);
        manager.addMessageFragment(frag);
        manager.addMessageFragment(fragment(0, 6, 5));
        assertFalse(manager.isFragmentedMessageComplete(frag));
    }

    @Test
    public void testIsMessageCompleteFalseEmpty() {
        DtlsHandshakeMessageFragment frag = fragment(0, 0, 5);
        assertFalse(manager.isFragmentedMessageComplete(frag));
    }

    @Test
    public void testClearFragmentedMessage() {
        DtlsHandshakeMessageFragment frag = fragment(0, 0, 5);
        manager.addMessageFragment(frag);
        manager.addMessageFragment(fragment(0, 5, 5));
        manager.clearFragmentedMessage(frag);
        assertFalse(manager.isFragmentedMessageComplete(frag));
        assertNull(manager.getFragmentedMessage(frag));
    }

    @Test
    public void testGetFragmentedMessageMultipleMessages() {
        manager.addMessageFragment(fragment(0, 0, 5, new byte[] { 0, 1, 2, 3, 4 }));
        manager.addMessageFragment(fragment(1, 0, 5, new byte[] { 8, 9, 10, 11, 12 }));
        manager.addMessageFragment(fragment(0, 5, 5, new byte[] { 5, 6, 7, 8, 9 }));
        assertNull(manager.getFragmentedMessage(1));
        DtlsHandshakeMessageFragment fragmentedMessage = manager.getFragmentedMessage(0);
        FragmentUtils.checkFragment(fragmentedMessage, 0, 10, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
    }

    @Test
    public void testGetFragmentedMessageDisordelyOverlapping() {
        manager.addMessageFragment(fragment(0, 0, 5, new byte[] { 0, 1, 2, 3, 4 }));
        manager.addMessageFragment(fragment(0, 7, 3, new byte[] { 7, 8, 9 }));
        manager.addMessageFragment(fragment(0, 5, 4, new byte[] { 5, 6, 7, 8 }));
        manager.addMessageFragment(fragment(0, 0, 5, new byte[] { 0, 1, 2, 3, 4 }));
        DtlsHandshakeMessageFragment fragmentedMessage = manager.getFragmentedMessage(0);
        FragmentUtils.checkFragment(fragmentedMessage, 0, 10, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
    }
}
