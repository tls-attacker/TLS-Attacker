/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.ice.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.constants.stun.StunVersionCookie;
import de.rub.nds.tlsattacker.core.ice.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.ice.model.MessageIntegrityAttribute;
import de.rub.nds.tlsattacker.core.ice.model.StunAttribute;
import de.rub.nds.tlsattacker.core.ice.model.StunMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class StunMessagePreparator extends IceMessagePreparator<StunMessage> {

    private StunMessage message;

    public StunMessagePreparator(Chooser chooser, StunMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepare() {
        message.setStunMessageClass(new byte[] {message.getClassType().getValue()});
        message.setStunMethodType(message.getMethodType().getValue());

        message.setStunMessageTypeBytes(
                encodeClassTypeWithMethodType(
                        message.getStunMethodType().getValue(),
                        message.getStunMessageClass().getValue()));
        // Message length can only be determined when all attributes are known
        if (chooser.getConfig().getIceConfig().isRandomizeStunTransactionIds()) {
            byte[] randomTransactionId = new byte[IceByteLengths.STUN_TRANSACTION_ID];
            RandomHelper.getRandom().nextBytes(randomTransactionId);
            // TODO Hardcode magic cookie
            randomTransactionId[0] = 0x21;
            randomTransactionId[1] = 0x12;
            randomTransactionId[2] = (byte) 0xA4;
            randomTransactionId[3] = 0x42;
            message.setTransactionId(randomTransactionId);
        } else {
            message.setTransactionId(chooser.getIceChooser().getStunTransactionId());
        }
        message.setMagicCookiePresent(isMagicCookiePresent());
        ByteArrayOutputStream attributeStream = new ByteArrayOutputStream();
        for (StunAttribute attribute : message.getAttributeList()) {
            if (attribute instanceof MessageIntegrityAttribute) {
                // For these attributes we need to fill the context with the message transcript
                byte[] fakeTranscript = computeTranscriptIntegrity(attributeStream.toByteArray());
                chooser.getContext().getIceContext().setMessageTranscript(fakeTranscript);
            }
            if (attribute instanceof FingerprintAttribute) {
                // For these attributes we need to fill the context with the message transcript
                byte[] fakeTranscript = computeTranscriptFingerprint(attributeStream.toByteArray());
                chooser.getContext().getIceContext().setMessageTranscript(fakeTranscript);
            }
            StunAttributePreparator<?> preparator =
                    attribute.getPreparator(chooser.getContext().getIceContext());
            preparator.prepare();
            try {
                attributeStream.write(
                        attribute.getSerializer(chooser.getContext().getIceContext()).serialize());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        message.setMessageLength(attributeStream.size());
    }

    @Override
    public void prepareAfterParse() {
        for (StunAttribute attribute : message.getAttributeList()) {
            attribute.getPreparator(chooser.getContext().getIceContext()).prepareAfterParse();
        }
    }

    private byte[] computeTranscriptFingerprint(byte[] currentAttributeStream) {
        ByteArrayOutputStream transcriptStream = new ByteArrayOutputStream();
        /**
         * The transcript contains everything before the message fingerprint attribute. The length
         * for the message field will be faked to include the message fingerprint attribute
         */
        try {
            transcriptStream.write(message.getStunMessageTypeBytes().getValue());
            int fakeLength =
                    currentAttributeStream.length
                            + IceByteLengths.STUN_ATTRIBUTE_TYPE
                            + IceByteLengths.STUN_ATTRIBUTE_LENGTH
                            + IceByteLengths.CRC32_CHECKSUM;
            transcriptStream.write(
                    ArrayConverter.intToBytes(fakeLength, IceByteLengths.STUN_MESSAGE_LENGTH));
            transcriptStream.write(message.getTransactionId().getValue());
            transcriptStream.write(currentAttributeStream);
            return transcriptStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Could not write to byte array output stream");
        }
    }

    private byte[] computeTranscriptIntegrity(byte[] currentAttributeStream) {
        ByteArrayOutputStream transcriptStream = new ByteArrayOutputStream();
        /**
         * The transcript contains everything before the message integrity attribute. The length for
         * the message field will be faked to include the message integrity attribute
         */
        try {
            transcriptStream.write(message.getStunMessageTypeBytes().getValue());
            int fakeLength =
                    currentAttributeStream.length
                            + IceByteLengths.STUN_ATTRIBUTE_TYPE
                            + IceByteLengths.STUN_ATTRIBUTE_LENGTH
                            + IceByteLengths.STUN_MESSAGE_INTEGRITY_HMAC;
            transcriptStream.write(
                    ArrayConverter.intToBytes(fakeLength, IceByteLengths.STUN_MESSAGE_LENGTH));
            transcriptStream.write(message.getTransactionId().getValue());
            transcriptStream.write(currentAttributeStream);
            return transcriptStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Could not write to byte array output stream");
        }
    }

    /**
     * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 +--+--+-+-+-+-+-+-+-+-+-+-+-+-+ |M |M
     * |M|M|M|C|M|M|M|C|M|M|M|M| |11|10|9|8|7|1|6|5|4|0|3|2|1|0| +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     * <p>Figure 3: Format of STUN Message Type Field
     *
     * <p>Here the bits in the STUN Message Type field are shown as most significant (M11) through
     * least significant (M0). M11 through M0 represent a 12-bit encoding of the method. C1 and C0
     * represent a 2-bit encoding of the class. A class of 0b00 is a request, a class of 0b01 is an
     * indication, a class of 0b10 is a success response, and a class of 0b11 is an error response.
     * This specification defines a single method, Binding. The method and class are orthogonal, so
     * that for each method, a request, success response, error response, and indication are
     * possible for that method. Extensions defining new methods MUST indicate which classes are
     * permitted for that method.
     *
     * <p>For example, a Binding request has class=0b00 (request) and method=0b000000000001
     * (Binding) and is encoded into the first 16 bits as 0x0001. A Binding response has class=0b10
     * (success response) and method=0b000000000001 and is encoded into the first 16 bits as 0x0101.
     */
    private byte[] encodeClassTypeWithMethodType(byte[] method, byte[] classType) {
        if (method.length != 2 || classType.length != 1) {
            throw new IllegalArgumentException(
                    "Method must be 2 bytes and class type must be 1 byte");
        }
        byte[] encoded = new byte[2];
        encoded[0] = (byte) ((method[0] & 0b00001111) << 2);
        encoded[0] |= (byte) ((method[1] & 0b10000000) >> 6);
        encoded[0] |= (byte) (classType[0] >> 1);

        encoded[1] = (byte) (((classType[0] & 0b00000001)) << 4);
        encoded[1] |= (byte) (method[1] & 0b00001111);
        encoded[1] |= (byte) ((method[1] & 0b01110000) >> 1);

        return encoded;
    }

    private boolean isMagicCookiePresent() {
        // Check if the first 4 bytes of the transaction id match the magic cookie
        byte[] magicCookie = StunVersionCookie.RFC5389_VERSION;
        byte[] transactionId = message.getTransactionId().getValue();
        if (transactionId.length < 4) {
            return false;
        }
        for (int i = 0; i < 4; i++) {
            if (magicCookie[i] != transactionId[i]) {
                return false;
            }
        }
        return true;
    }
}
