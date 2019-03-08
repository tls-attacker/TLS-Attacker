package de.rub.nds.tlsattacker.core.dtls;

import static de.rub.nds.tlsattacker.core.dtls.FragmentUtils.fragment;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;

public class FragmentManagerTest {
	
	private FragmentManager manager;

	@Before
	public void setUp() {
		manager = new FragmentManager();
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
	public void testIsMessageCompleteMultipleMessages() {
		DtlsHandshakeMessageFragment frag1 = fragment(0, 0, 5);
		manager.addMessageFragment(frag1);
		DtlsHandshakeMessageFragment frag2 = fragment(1, 0, 5);
		manager.addMessageFragment(frag2);
		manager.addMessageFragment(fragment(0, 5, 5));
		assertTrue(manager.isFragmentedMessageComplete(frag1));
		assertFalse(manager.isFragmentedMessageComplete(frag2));
	}
	
	@Test
	public void testClearFragmentedMessage() {
		DtlsHandshakeMessageFragment frag = fragment(0, 0, 5);
		manager.addMessageFragment(frag);
		manager.addMessageFragment(fragment(0, 5, 5));
		manager.clearFragmentedMessage(frag);
		assertFalse(manager.isFragmentedMessageComplete(frag));
	}
}
