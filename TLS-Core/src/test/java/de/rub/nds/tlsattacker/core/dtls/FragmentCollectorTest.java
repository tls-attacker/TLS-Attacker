/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.dtls;

import static de.rub.nds.tlsattacker.core.dtls.FragmentUtils.*;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class FragmentCollectorTest {

    private FragmentCollector collector;

    @BeforeEach
    public void setUp() {
        collector = new FragmentCollector(Config.createConfig(), (byte) 0, 0, 10);
    }

    /** Test that addFragment is successful. (Does not throw an exception */
    @Test
    public void testAddTrue() {
        collector.addFragment(fragment(0, 0, 10, 0));
    }

    /** Test that adding the same fragment twice is not a problem. */
    @Test
    public void testAddFalse() {
        DtlsHandshakeMessageFragment frag = fragment(0, 0, 10, 0);
        collector.addFragment(frag);
        collector.addFragment(frag);
    }

    /** Test isMessageComplete when all fragments are inserted orderly. */
    @Test
    public void testIsMessageCompleteTrue() {
        collector.addFragment(fragment(0, 0, 5, 0));
        collector.addFragment(fragment(0, 5, 5, 0));
        assertTrue(collector.isMessageComplete());
    }

    /** Test isMessageComplete when there is a missing byte. */
    @Test
    public void testIsMessageCompleteFalse() {
        collector.addFragment(fragment(0, 0, 5, 0));
        collector.addFragment(fragment(0, 6, 4, 0));
        assertFalse(collector.isMessageComplete());
    }

    /** Test isMessageComplete when all fragments are inserted disorderly. */
    @Test
    public void testIsMessageCompleteDisorderlyTrue() {
        collector.addFragment(fragment(0, 0, 2, 0));
        collector.addFragment(fragment(0, 8, 2, 0));
        collector.addFragment(fragment(0, 5, 3, 0));
        collector.addFragment(fragment(0, 2, 3, 0));
        assertTrue(collector.isMessageComplete());
    }

    /** Test isMessageComplete when all fragments are inserted disorderly with overlap. */
    @Test
    public void testIsMessageCompleteTrueDisorderlyOverlap() {
        collector.addFragment(fragment(0, 5, 3, 0));
        collector.addFragment(fragment(0, 7, 3, 0));
        collector.addFragment(fragment(0, 0, 3, 0));
        collector.addFragment(fragment(0, 2, 4, 0));
        assertTrue(collector.isMessageComplete());
    }

    /**
     * Test isMessageComplete when all fragments are inserted disorderly with overlap a few bytes
     * are missing.
     */
    @Test
    public void testIsMessageCompleteFalseDisorderlyOverlap() {
        collector.addFragment(fragment(0, 6, 3, 0));
        collector.addFragment(fragment(0, 0, 7, 0));
        assertFalse(collector.isMessageComplete());
    }

    /** Test isFitting for unfitting fragments. */
    @Test
    public void testIsFittingFalse() {
        collector.addFragment(fragment(0, 0, 7, 0));
        DtlsHandshakeMessageFragment badSeq = fragment(0, 6, 3, 0);
        badSeq.setMessageSequence(1000);
        assertFalse(collector.isFitting(badSeq));
        DtlsHandshakeMessageFragment badLength = fragment(0, 6, 3, 0);
        badLength.setLength(1000);
        assertFalse(collector.isFitting(badLength));
        DtlsHandshakeMessageFragment badType = fragment(0, 6, 3, 0);
        badType.setType(Byte.MAX_VALUE);
        assertFalse(collector.isFitting(badType));
    }

    /** Test isFitting for fragment which has the same type as a previously added fragment. */
    @Test
    public void testIsFittingTrue() {
        collector.addFragment(fragment(0, 0, 7, 0));
        DtlsHandshakeMessageFragment frag = fragment(0, 6, 3, 0);
        frag.setType((byte) 0);
        assertTrue(collector.isFitting(frag));
    }

    /** Test buildCombinedFragment in the usual case. */
    @Test
    public void testBuildCombinedFragment() {
        byte[] original = ArrayConverter.hexStringToByteArray("123456789A123456789A");
        collector.addFragment(fragmentOfMsg(0, 0, 3, original, 0));
        collector.addFragment(fragmentOfMsg(0, 3, 5, original, 0));
        collector.addFragment(fragmentOfMsg(0, 8, 2, original, 0));
        DtlsHandshakeMessageFragment fragment = collector.buildCombinedFragment();
        assertFragment(fragment, 0, 10, original);
    }

    /** Test buildCombinedFragment when fragments have been inserted disorderly with overlaps. */
    @Test
    public void testBuildCombinedFragmentDisorderlyOverlap() {
        byte[] original = ArrayConverter.hexStringToByteArray("123456789A123456789A");
        collector.addFragment(fragmentOfMsg(0, 5, 5, original, 0));
        collector.addFragment(fragmentOfMsg(0, 0, 3, original, 0));
        collector.addFragment(fragmentOfMsg(0, 2, 4, original, 0));
        DtlsHandshakeMessageFragment fragment = collector.buildCombinedFragment();
        assertFragment(fragment, 0, 10, original);
    }

    /** Test buildCombinedFragment when not all bytes have been received. */
    @Test
    public void testBuildCombinedFragmentIncomplete() {
        byte[] original = ArrayConverter.hexStringToByteArray("123456789A123456789A");
        collector.addFragment(fragmentOfMsg(0, 0, 5, original, 0));
        collector.addFragment(fragmentOfMsg(0, 6, 4, original, 0));
        DtlsHandshakeMessageFragment fragment = collector.buildCombinedFragment();
        byte[] expected = ArrayConverter.hexStringToByteArray("123456789A3456789A");
        assertFragment(fragment, 0, 10, expected);
    }

    /**
     * Test buildCombinedFragment after adding an unfitting fragment, with only fitting set to
     * false.
     */
    @Test
    public void testBuildCombinedFragmentAddUnfitting() {
        Config config = Config.createConfig();
        config.setAcceptOnlyFittingDtlsFragments(false);
        collector = new FragmentCollector(config, (byte) 0, 6, 10);
        byte[] original = ArrayConverter.hexStringToByteArray("123456789A123456789A");
        collector.addFragment(fragmentOfMsg(0, 0, 5, original, 0));
        DtlsHandshakeMessageFragment unfitting = fragmentOfMsg(0, 6, 4, original, 0);
        unfitting.setLength(20);
        collector.addFragment(unfitting);
        DtlsHandshakeMessageFragment fragment = collector.buildCombinedFragment();
        byte[] expected = ArrayConverter.hexStringToByteArray("123456789A3456789A");
        assertFragment(fragment, 0, 10, expected);
    }
}
