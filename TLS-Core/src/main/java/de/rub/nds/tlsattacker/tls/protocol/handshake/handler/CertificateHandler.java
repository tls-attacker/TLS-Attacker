/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.tls.protocol.handshake.handler;

import de.rub.nds.tlsattacker.tls.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.tls.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.tls.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.tls.exceptions.InvalidMessageTypeException;
import de.rub.nds.tlsattacker.tls.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.tls.protocol.handshake.CertificateMessage;
import de.rub.nds.tlsattacker.tls.util.JKSLoader;
import de.rub.nds.tlsattacker.tls.workflow.TlsContext;
import de.rub.nds.tlsattacker.transport.ConnectionEnd;
import de.rub.nds.tlsattacker.util.ArrayConverter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.util.Arrays;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.X509CertificateObject;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class CertificateHandler extends HandshakeMessageHandler<CertificateMessage> {

    public CertificateHandler(TlsContext tlsContext) {
        super(tlsContext);
        this.correctProtocolMessageClass = CertificateMessage.class;
    }

    @Override
    public byte[] prepareMessageAction() {
        ByteArrayOutputStream tlsCertBos = new ByteArrayOutputStream();
        try {
            JKSLoader.loadTLSCertificate(tlsContext.getConfig().getKeyStore(), tlsContext.getConfig().getAlias())
                    .encode(tlsCertBos);
        } catch (IOException ex) {
            throw new ConfigurationException("Could not load Certificate for CertificateMessage!", ex);
        }
        protocolMessage.setX509CertificateBytes(tlsCertBos.toByteArray());
        protocolMessage.setCertificatesLength(protocolMessage.getX509CertificateBytes().getValue().length
                - HandshakeByteLength.CERTIFICATES_LENGTH);
        protocolMessage.setLength(protocolMessage.getX509CertificateBytes().getValue().length);
        byte[] result = protocolMessage.getX509CertificateBytes().getValue();
        long header = (protocolMessage.getHandshakeMessageType().getValue() << 24)
                + protocolMessage.getLength().getValue();
        protocolMessage.setCompleteResultingMessage(ArrayConverter.concatenate(
                ArrayConverter.longToUint32Bytes(header), result));
        return protocolMessage.getCompleteResultingMessage().getValue();
    }

    @Override
    public int parseMessageAction(byte[] message, int pointer) {
        if (message[pointer] != HandshakeMessageType.CERTIFICATE.getValue()) {
            throw new InvalidMessageTypeException("This is not a certificate message");
        }
        protocolMessage.setType(message[pointer]);

        int currentPointer = pointer + HandshakeByteLength.MESSAGE_TYPE;
        int nextPointer = currentPointer + HandshakeByteLength.MESSAGE_TYPE_LENGTH;
        int length = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
        protocolMessage.setLength(length);

        currentPointer = nextPointer;
        nextPointer = currentPointer + HandshakeByteLength.CERTIFICATES_LENGTH;
        int certificatesLength = ArrayConverter.bytesToInt(Arrays.copyOfRange(message, currentPointer, nextPointer));
        protocolMessage.setCertificatesLength(certificatesLength);

        try {
            Certificate tlsCerts = Certificate.parse(new ByteArrayInputStream(message, currentPointer, protocolMessage
                    .getCertificatesLength().getValue() + HandshakeByteLength.CERTIFICATES_LENGTH));
            X509CertificateObject x509CertObject = new X509CertificateObject(tlsCerts.getCertificateAt(0));
            if (tlsContext.getConfig().getMyConnectionPeer() == ConnectionEnd.SERVER) {
                tlsContext.setServerCertificate(tlsCerts);
            } else {
                tlsContext.setClientCertificate(tlsCerts);
            }
        } catch (IOException | CertificateParsingException ex) {
            throw new WorkflowExecutionException(ex.getLocalizedMessage(), ex);
        }
        nextPointer += protocolMessage.getCertificatesLength().getValue();

        protocolMessage.setCompleteResultingMessage(Arrays.copyOfRange(message, pointer, nextPointer));

        return nextPointer;
    }
}
