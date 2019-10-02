/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.dtls;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import static de.rub.nds.tlsattacker.core.dtls.FragmentUtils.checkFragment;
import static de.rub.nds.tlsattacker.core.dtls.FragmentUtils.fragment;
import static de.rub.nds.tlsattacker.core.dtls.FragmentUtils.fragmentOfMsg;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

public class FragmentCollectorTest {

    private FragmentCollector collector;

    @Before
    public void setUp() {
        collector = new FragmentCollector(Config.createConfig());
    }

    /**
     * Test that addFragment is successful.
     */
    @Test
    public void testAddTrue() {
        assertTrue(collector.addFragment(fragment(0, 0, 10)));
    }

    /**
     * Test that one cannot add the same fragment twice.
     */
    @Test
    public void testAddFalse() {
        DtlsHandshakeMessageFragment frag = fragment(0, 0, 10);
        collector.addFragment(frag);
        assertFalse(collector.addFragment(frag));
    }

    /**
     * Test isMessageComplete when all fragments are inserted orderly.
     */
    @Test
    public void testIsMessageCompleteTrue() {
        collector.addFragment(fragment(0, 0, 5));
        collector.addFragment(fragment(0, 5, 5));
        assertTrue(collector.isMessageComplete());
    }

    /**
     * Test isMessageComplete when there is a missing byte.
     */
    @Test
    public void testIsMessageCompleteFalse() {
        collector.addFragment(fragment(0, 0, 5));
        collector.addFragment(fragment(0, 6, 4));
        assertFalse(collector.isMessageComplete());
    }

    /**
     * Test isMessageComplete when all fragments are inserted disorderly.
     */
    @Test
    public void testIsMessageCompleteDisordelyTrue() {
        collector.addFragment(fragment(0, 0, 2));
        collector.addFragment(fragment(0, 8, 2));
        collector.addFragment(fragment(0, 5, 3));
        collector.addFragment(fragment(0, 2, 3));
        assertTrue(collector.isMessageComplete());
    }

    /**
     * Test isMessageComplete when all fragments are inserted disorderly with
     * overlap.
     */
    @Test
    public void testIsMessageCompleteTrueDisordelyOverlap() {
        collector.addFragment(fragment(0, 5, 3));
        collector.addFragment(fragment(0, 7, 3));
        collector.addFragment(fragment(0, 0, 3));
        collector.addFragment(fragment(0, 2, 4));
        assertTrue(collector.isMessageComplete());
    }

    /**
     * Test isMessageComplete when all fragments are inserted disorderly with
     * overlap a few bytes are missing.
     */
    @Test
    public void testIsMessageCompleteFalseDisordelyOverlap() {
        collector.addFragment(fragment(0, 6, 3));
        collector.addFragment(fragment(0, 0, 7));
        assertFalse(collector.isMessageComplete());
    }

    /**
     * Test isFitting for unfitting fragments.
     */
    @Test
    public void testIsFittingFalse() {
        collector.addFragment(fragment(0, 0, 7));
        DtlsHandshakeMessageFragment badSeq = fragment(0, 6, 3);
        badSeq.setMessageSeq(1000);
        assertFalse(collector.isFitting(badSeq));
        DtlsHandshakeMessageFragment badLength = fragment(0, 6, 3);
        badLength.setLength(1000);
        assertFalse(collector.isFitting(badLength));
        DtlsHandshakeMessageFragment badType = fragment(0, 6, 3);
        badType.setType(Byte.MAX_VALUE);
        assertFalse(collector.isFitting(badType));
    }

    /**
     * Test isEmpty true case.
     */
    @Test
    public void testIsEmptyTrue() {
        assertTrue(collector.isEmpty());
    }

    /**
     * Test isEmpty false case.
     */
    @Test
    public void testIsEmptyFalse() {
        collector.addFragment(fragment(0, 0, 7));
        assertFalse(collector.isEmpty());
    }

    /**
     * Test isFitting for fragment which has the same type as a previously added
     * fragment.
     */
    @Test
    public void testIsFittingTrue() {
        collector.addFragment(fragment(0, 0, 7));
        DtlsHandshakeMessageFragment frag = fragment(0, 6, 3);
        assertTrue(collector.isFitting(frag));
    }

    /**
     * Test isFitting for fragment which should fit since collector is empty.
     */
    @Test
    public void testIsFittingTrueEmpty() {
        DtlsHandshakeMessageFragment frag = fragment(0, 6, 3);
        frag.setMessageSeq(1000);
        assertTrue(collector.isFitting(frag));
    }

    /**
     * Test buildCombinedFragment in the usual case.
     */
    @Test
    public void testbuildCombinedFragment() {
        byte[] original = ArrayConverter.hexStringToByteArray("123456789A123456789A");
        collector.addFragment(fragmentOfMsg(0, 0, 3, original));
        collector.addFragment(fragmentOfMsg(0, 3, 5, original));
        collector.addFragment(fragmentOfMsg(0, 8, 2, original));
        DtlsHandshakeMessageFragment fragment = collector.buildCombinedFragment();
        checkFragment(fragment, 0, 10, original);
    }

    /**
     * Test buildCombinedFragment when fragments have been inserted disorderly
     * with overlaps.
     */
    @Test
    public void testbuildCombinedFragmentDisorderlyOverlap() {
        byte[] original = ArrayConverter.hexStringToByteArray("123456789A123456789A");
        collector.addFragment(fragmentOfMsg(0, 5, 5, original));
        collector.addFragment(fragmentOfMsg(0, 0, 3, original));
        collector.addFragment(fragmentOfMsg(0, 2, 4, original));
        DtlsHandshakeMessageFragment fragment = collector.buildCombinedFragment();
        checkFragment(fragment, 0, 10, original);
    }

    /**
     * Test buildCombinedFragment when not all bytes have been received.
     */
    @Test
    public void testbuildCombinedFragmentIncomplete() {
        byte[] original = ArrayConverter.hexStringToByteArray("123456789A123456789A");
        collector.addFragment(fragmentOfMsg(0, 0, 5, original));
        collector.addFragment(fragmentOfMsg(0, 6, 4, original));
        DtlsHandshakeMessageFragment fragment = collector.buildCombinedFragment();
        byte[] expected = ArrayConverter.hexStringToByteArray("123456789A003456789A");
        checkFragment(fragment, 0, 10, expected);
    }

    private FragmentCollector generateOnlyFittingFalseCollector() {
        Config config = Config.createEmptyConfig();
        config.setDtlsOnlyFitting(false);
        return new FragmentCollector(config);
    }

    /**
     * Test buildCombinedFragment after adding an unfitting fragment, with only
     * fitting set to false.
     */
    @Test
    public void testbuildCombinedFragmentAddUnfitting() {
        collector = generateOnlyFittingFalseCollector();
        byte[] original = ArrayConverter.hexStringToByteArray("123456789A123456789A");
        collector.addFragment(fragmentOfMsg(0, 0, 5, original));
        DtlsHandshakeMessageFragment unfitting = fragmentOfMsg(0, 6, 4, original);
        unfitting.setLength(20);
        collector.addFragment(unfitting);
        DtlsHandshakeMessageFragment fragment = collector.buildCombinedFragment();
        byte[] expected = ArrayConverter.hexStringToByteArray("123456789A003456789A");
        checkFragment(fragment, 0, 10, expected);
    }
}
