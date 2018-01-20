/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.preparator;

import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.SSL2ClientMasterKeyMessage;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;

public class SSL2ClientMasterKeyPreparator extends ProtocolMessagePreparator {

    private final SSL2ClientMasterKeyMessage message;

    public SSL2ClientMasterKeyPreparator(Chooser chooser, SSL2ClientMasterKeyMessage message) {
        super(chooser, message);
        this.message = message;
    }

    @Override
    protected void prepareProtocolMessageContents() {
        // private ModifiableByteArray cipherKind;
        //
        // @ModifiableVariableProperty(type =
        // ModifiableVariableProperty.Type.LENGTH)
        // private ModifiableInteger clearKeyLength;
        //
        // @ModifiableVariableProperty(type =
        // ModifiableVariableProperty.Type.LENGTH)
        // private ModifiableInteger encryptedKeyLength;
        //
        // @ModifiableVariableProperty(type =
        // ModifiableVariableProperty.Type.LENGTH)
        // private ModifiableInteger keyArgLength;
        //
        // @ModifiableVariableProperty(type =
        // ModifiableVariableProperty.Type.KEY_MATERIAL)
        // private ModifiableByteArray clearKeyData;
        //
        // @ModifiableVariableProperty(type =
        // ModifiableVariableProperty.Type.KEY_MATERIAL)
        // private ModifiableByteArray encryptedKeyData;
        //
        // @ModifiableVariableProperty(type =
        // ModifiableVariableProperty.Type.KEY_MATERIAL)
        // private ModifiableByteArray keyArgData;

        LOGGER.debug("Prepare SSL2ClientMasterKey");
        prepareType(message);
        prepareCipherKind(message);
        prepareClearKey(message);
        prepareClearKeyLength(message);

        LOGGER.debug("RSA Modulus: ", chooser.getServerRsaModulus().toString());

        // byte[] challenge = new byte[16];
        // chooser.getContext().getRandom().nextBytes(challenge);
        // prepareChallenge(message, challenge);
        // prepareSessionID(message);
        // prepareSessionIDLength(message);
        // prepareChallengeLength(message);
        // prepareCipherSuiteLength(message);
        // int length = SSL2ByteLength.CHALLENGE_LENGTH +
        // SSL2ByteLength.CIPHERSUITE_LENGTH + SSL2ByteLength.MESSAGE_TYPE
        // + SSL2ByteLength.SESSIONID_LENGTH;
        // length += message.getChallenge().getValue().length;
        // length += message.getCipherSuites().getValue().length;
        // length += message.getSessionId().getValue().length;
        // length += message.getProtocolVersion().getValue().length;
        // prepareMessageLength(message, length);
    }

    private void prepareType(SSL2ClientMasterKeyMessage message) {
        message.setType(HandshakeMessageType.SSL2_CLIENT_MASTER_KEY.getValue());
        LOGGER.debug("Type: " + message.getType().getValue());
    }

    private void prepareCipherKind(SSL2ClientMasterKeyMessage message) {
        // by default we currently just try export RC4
        message.setCipherKind(ArrayConverter.hexStringToByteArray("020080"));
        LOGGER.debug("CipherKind: " + ArrayConverter.bytesToHexString(message.getCipherKind().getValue()));
    }

    private void prepareClearKey(SSL2ClientMasterKeyMessage message) {
        // by default we currently supply 11 null bytes
        message.setClearKeyData(new byte[11]);
        LOGGER.debug("ClearKey: " + ArrayConverter.bytesToHexString(message.getClearKeyData().getValue()));
    }

    private void prepareClearKeyLength(SSL2ClientMasterKeyMessage message) {
        message.setClearKeyLength(message.getClearKeyData().getValue().length);
        LOGGER.debug("ClearKeyLength: " + message.getClearKeyLength().getValue());
    }

    private void prepareMessageLength(SSL2ClientMasterKeyMessage message, int length) {
        message.setMessageLength(length ^ 0x8000);
        LOGGER.debug("MessageLength: " + message.getMessageLength().getValue());
    }

}
