package de.rub.nds.tlsattacker.core.dtls;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import org.bouncycastle.util.Arrays;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;

public class FragmentUtils {
	public static final int DEFAULT_MESSAGE_LENGTH = 10;
	
	public static DtlsHandshakeMessageFragment fragment(int messageSeq, int fragmentOffset, int fragmentLength,
			byte content[]) {
		DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment();
		fragment.setFragmentOffset(fragmentOffset);
		fragment.setFragmentLength(fragmentLength);
		fragment.setMessageSeq(messageSeq);
		fragment.setContent(content);
		fragment.setLength(DEFAULT_MESSAGE_LENGTH);
		fragment.setType(HandshakeMessageType.UNKNOWN.getValue());
		return fragment;
	}
	
	public static DtlsHandshakeMessageFragment fragment(int messageSeq, int fragmentOffset, int fragmentLength) {
		return fragment(messageSeq, fragmentOffset, fragmentLength, new byte[fragmentLength]);
	}
	
	public static DtlsHandshakeMessageFragment fragmentOfMsg(int messageSeq, int fragmentOffset, int fragmentLength,
			byte msgContent[]) {
		byte content [] = Arrays.copyOfRange(msgContent, fragmentOffset, fragmentOffset+fragmentLength);
		return fragment(messageSeq, fragmentOffset, fragmentLength, content);
	}
	
	public static void checkFragment(DtlsHandshakeMessageFragment fragment, int expectedOffset, 
			int expectedLength, byte [] expectedContent) {
		assertEquals(fragment.getFragmentOffset().getValue().intValue(), expectedOffset);
		assertEquals(fragment.getFragmentLength().getValue().intValue(), expectedLength);
		assertArrayEquals(fragment.getContent().getValue(), expectedContent);
		assertEquals(fragment.getLength().getValue().intValue(), DEFAULT_MESSAGE_LENGTH);
	}
}
