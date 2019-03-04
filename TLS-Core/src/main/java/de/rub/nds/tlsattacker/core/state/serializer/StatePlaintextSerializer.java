/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.state.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ClientAuthenticationType;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.state.StatePlaintext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StatePlaintextSerializer extends Serializer<StatePlaintext> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final StatePlaintext statePlaintext;

    public StatePlaintextSerializer(StatePlaintext statePlaintext) {
        this.statePlaintext = statePlaintext;
    }

    @Override
    protected byte[] serializeBytes() {
        LOGGER.debug("Serializing StatePlaintext");
        writeProtocolVersion(statePlaintext);
        writeCipherSuite(statePlaintext);
        writeCompressionMethod(statePlaintext);
        writeMasterSecret(statePlaintext);
        writeClientAuthentication(statePlaintext);
        writeTimestamp(statePlaintext);
        return getAlreadySerialized();
    }

    private void writeProtocolVersion(StatePlaintext statePlaintext) {
        appendBytes(statePlaintext.getProtocolVersion().getValue());
        LOGGER.debug("ProtocolVersion: "
                + ProtocolVersion.getProtocolVersion(statePlaintext.getProtocolVersion().getValue()).name());
    }

    private void writeCipherSuite(StatePlaintext statePlaintext) {
        appendInt(statePlaintext.getCipherSuite().getValue(), HandshakeByteLength.CIPHER_SUITE);
        LOGGER.debug("CipherSuite: " + CipherSuite.getCipherSuite(statePlaintext.getCipherSuite().getValue()).name());
    }

    private void writeCompressionMethod(StatePlaintext statePlaintext) {
        appendByte(statePlaintext.getCompressionMethod().getValue());
        LOGGER.debug("CompressionMethod: "
                + CompressionMethod.getCompressionMethod(statePlaintext.getCompressionMethod().getValue()).name());
    }

    private void writeMasterSecret(StatePlaintext statePlaintext) {
        appendBytes(statePlaintext.getMasterSecret().getValue());
        LOGGER.debug("MasterSecret: "
                + ArrayConverter.bytesToHexString(statePlaintext.getMasterSecret().getValue(), true, true));
    }

    private void writeClientAuthentication(StatePlaintext statePlaintext) {
        byte clientAuthenticationType = statePlaintext.getClientAuthenticationType().getValue();
        if (clientAuthenticationType == ClientAuthenticationType.ANONYMOUS.getValue()) {
            appendByte(clientAuthenticationType);
            LOGGER.debug("ClientAuthenticationType: "
                    + ClientAuthenticationType.getClientAuthenticationType(clientAuthenticationType).name());
        } else if (clientAuthenticationType == ClientAuthenticationType.CERTIFICATE_BASED.getValue()) {
            appendByte(clientAuthenticationType);
            appendBytes(statePlaintext.getClientAuthenticationDataLength().getByteArray(
                    HandshakeByteLength.CERTIFICATES_LENGTH));
            appendBytes(statePlaintext.getClientAuthenticationData().getValue());
            LOGGER.debug("ClientAuthenticationType: "
                    + ClientAuthenticationType.getClientAuthenticationType(clientAuthenticationType).name());
            LOGGER.debug("ClientAuthenticationDataLength: "
                    + statePlaintext.getClientAuthenticationDataLength().getValue());
            LOGGER.debug("ClientAuthenticationData: "
                    + ArrayConverter.bytesToHexString(statePlaintext.getClientAuthenticationData().getValue(), true,
                            true));
        } else if (clientAuthenticationType == ClientAuthenticationType.PSK.getValue()) {
            appendByte(clientAuthenticationType);
            appendBytes(statePlaintext.getClientAuthenticationDataLength().getByteArray(
                    HandshakeByteLength.PSK_IDENTITY_LENGTH));
            appendBytes(statePlaintext.getClientAuthenticationData().getValue());
            LOGGER.debug("ClientAuthenticationType: "
                    + ClientAuthenticationType.getClientAuthenticationType(clientAuthenticationType).name());
            LOGGER.debug("ClientAuthenticationDataLength: "
                    + statePlaintext.getClientAuthenticationDataLength().getValue());
            LOGGER.debug("ClientAuthenticationData: "
                    + ArrayConverter.bytesToHexString(statePlaintext.getClientAuthenticationData().getValue(), true,
                            true));
        } else {
            appendByte(clientAuthenticationType);
            LOGGER.warn("Can't serialize ClientAuthticationData because the choosen ClientAuthType is unknown: "
                    + clientAuthenticationType);
        }
    }

    private void writeTimestamp(StatePlaintext statePlaintext) {
        appendBytes(statePlaintext.getTimestamp().getByteArray(HandshakeByteLength.UNIX_TIME));
        LOGGER.debug("Timestamp: "
                + ArrayConverter.bytesToHexString(statePlaintext.getTimestamp().getByteArray(
                        HandshakeByteLength.UNIX_TIME)));
    }
}
