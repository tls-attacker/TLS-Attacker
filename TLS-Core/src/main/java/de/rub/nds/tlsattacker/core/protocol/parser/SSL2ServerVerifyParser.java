package de.rub.nds.tlsattacker.core.protocol.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ServerVerifyMessage;

public class SSL2ServerVerifyParser extends ProtocolMessageParser<SSL2ServerVerifyMessage> {

    public SSL2ServerVerifyParser(byte[] message, int pointer, ProtocolVersion selectedProtocolVersion) {
        super(pointer, message, selectedProtocolVersion);
    }

    @Override
    protected SSL2ServerVerifyMessage parseMessageContent() {
        LOGGER.debug("Parsing SSL2ServerVerify");
        SSL2ServerVerifyMessage message = new SSL2ServerVerifyMessage();
        parseMessageLength(message);
        parseEncryptedPart(message);
        return message;
    }

	private void parseEncryptedPart(SSL2ServerVerifyMessage message) {
        message.setEncryptedPart(parseByteArrayField(message.getMessageLength().getValue()));
        LOGGER.debug("Encrypted Part: " + ArrayConverter.bytesToHexString(message.getEncryptedPart().getValue()));
	}

	// TODO: de-duplicate
    private void parseMessageLength(SSL2ServerVerifyMessage message) {
        // The "wonderful" SSL2 message length field:
        // 2-byte header: RECORD-LENGTH = ((byte[0] & 0x7f) << 8)) | byte[1];
        // 3-byte header: RECORD-LENGTH = ((byte[0] & 0x3f) << 8)) | byte[1];
        // If most significant bit on first byte is set: 2-byte header.
        // O/w, 3-byte header.
        byte[] first2Bytes = parseByteArrayField(2);
        int mask;
        if ((first2Bytes[0] & 0x80) == 0) {
            mask = 0x3f;
        } else {
            mask = 0x7f;
        }
        int len = ((first2Bytes[0] & mask) << 8) | (first2Bytes[1] & 0xFF);
        message.setMessageLength(len);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

}
