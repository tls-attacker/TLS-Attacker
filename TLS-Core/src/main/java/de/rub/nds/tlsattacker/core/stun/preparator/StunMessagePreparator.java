/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.stun.preparator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.stun.IceByteLengths;
import de.rub.nds.tlsattacker.core.constants.stun.StunVersionCookie;
import de.rub.nds.tlsattacker.core.layer.data.Preparator;
import de.rub.nds.tlsattacker.core.stun.model.FingerprintAttribute;
import de.rub.nds.tlsattacker.core.stun.model.MessageIntegrityAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunAttribute;
import de.rub.nds.tlsattacker.core.stun.model.StunMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class StunMessagePreparator extends Preparator<StunMessage> {

    private StunMessage message;

    public StunMessagePreparator(Chooser chooser, StunMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    public void prepare() {
        message.setStunMessageClass(new byte[] { message.getClassType().getValue() });
        message.setStunMethodType(message.getMethodType().getValue());

        message.setStunMessageTypeBytes(
                encodeClassTypeWithMethodType(
                        message.getStunMethodType().getValue(),
                        message.getStunMessageClass().getValue()));
        // Message length can only be determined when all attributes are known

        message.setTransactionId(chooser.getIceChooser().getStunTransactionId());
        message.setMagicCookiePresent(isMagicCookiePresent());
        ByteArrayOutputStream attributeStream = new ByteArrayOutputStream();
        for (StunAttribute attribute : message.getAttributeList()) {
            if (attribute instanceof MessageIntegrityAttribute) {
                //For these attributes we need to fill the context with the message transcript
                byte[] fakeTranscript = computeTranscriptIntegrity(attributeStream.toByteArray());
                chooser.getContext().getIceContext().setMessageTranscript(fakeTranscript);
            }
            if (attribute instanceof FingerprintAttribute) {
                //For these attributes we need to fill the context with the message transcript
                byte[] fakeTranscript = computeTranscriptFingerprint(attributeStream.toByteArray());
                chooser.getContext().getIceContext().setMessageTranscript(fakeTranscript);
            }
            StunAttributePreparator<?> preparator = attribute.getPreparator(chooser.getContext().getIceContext());
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

    private byte[] computeTranscriptFingerprint(byte[] currentAttributeStream) {
        ByteArrayOutputStream transcriptStream = new ByteArrayOutputStream();
        /**
         * The transcript contains everything before the message fingerprint attribute. The length for the message field will be
         * faked to include the message fingerprint attribute
         */
        try {
            transcriptStream.write(message.getStunMessageTypeBytes().getValue());
            int fakeLength = currentAttributeStream.length + IceByteLengths.STUN_ATTRIBUTE_TYPE
                    + IceByteLengths.STUN_ATTRIBUTE_LENGTH + IceByteLengths.CRC32_CHECKSUM;
            transcriptStream.write(ArrayConverter.intToBytes(fakeLength, IceByteLengths.STUN_MESSAGE_LENGTH));
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
         * The transcript contains everything before the message integrity attribute. The length for the message field will be
         * faked to include the message integrity attribute
         */
        try {
            transcriptStream.write(message.getStunMessageTypeBytes().getValue());
            int fakeLength = currentAttributeStream.length + IceByteLengths.STUN_ATTRIBUTE_TYPE
                    + IceByteLengths.STUN_ATTRIBUTE_LENGTH + IceByteLengths.STUN_MESSAGE_INTEGRITY_HMAC;
            transcriptStream.write(ArrayConverter.intToBytes(fakeLength, IceByteLengths.STUN_MESSAGE_LENGTH));
            transcriptStream.write(message.getTransactionId().getValue());
            transcriptStream.write(currentAttributeStream);
            return transcriptStream.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Could not write to byte array output stream");
        }

    }

    private byte[] encodeClassTypeWithMethodType(byte[] method, byte[] classType) {
        int methodInt = ArrayConverter.bytesToInt(method);
        int classInt = ArrayConverter.bytesToInt(classType);
        int encoded = (methodInt & 0x1F80) << 2
                | (methodInt & 0x0070) << 1
                | (methodInt & 0x000F)
                | (classInt & 0x0002) << 7
                | (classInt & 0x0001) << 4;
        return ArrayConverter.intToBytes(encoded, IceByteLengths.STUN_MESSAGE_TYPE);
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
