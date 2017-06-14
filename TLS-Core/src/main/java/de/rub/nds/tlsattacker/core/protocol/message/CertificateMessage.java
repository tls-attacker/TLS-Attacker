/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateMessageSerializer;
import de.rub.nds.tlsattacker.core.protocol.serializer.Serializer;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.protocol.message.Cert.CertificatePair;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
import org.bouncycastle.crypto.tls.Certificate;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
@XmlRootElement
public class CertificateMessage extends HandshakeMessage {

    /**
     * request context length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger requestContextLength;
    /**
     * request context
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.NONE)
    private ModifiableByteArray requestContext;

    /**
     * certificates length
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificatesListLength;

    @ModifiableVariableProperty
    private ModifiableByteArray certificatesListBytes;

    @HoldsModifiableVariable
    private List<CertificatePair> certificatesList;

    public CertificateMessage() {
        super(HandshakeMessageType.CERTIFICATE);
    }

    public CertificateMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.CERTIFICATE);
        if (tlsConfig.getHighestProtocolVersion() == ProtocolVersion.TLS13) {
            CertificatePair pair = new CertificatePair();
            if (tlsConfig.getOurCertificate() == null) {
                throw new CryptoException("No certificate is specified for " + tlsConfig.getConnectionEnd().name());
            }
            byte[] cert = encodeCert(tlsConfig.getOurCertificate());
            pair.setCertificateConfig(cert);
            pair.setExtensionsConfig(tlsConfig.getOurCertificateExtensions());
            addCertificateList(pair);
        }
    }

    public ModifiableInteger getCertificatesListLength() {
        return certificatesListLength;
    }

    public void setCertificatesListLength(ModifiableInteger certificatesListLength) {
        this.certificatesListLength = certificatesListLength;
    }

    public void setCertificatesListLength(int length) {
        this.certificatesListLength = ModifiableVariableFactory.safelySetValue(certificatesListLength, length);
    }

    public ModifiableByteArray getCertificatesListBytes() {
        return certificatesListBytes;
    }

    public void setCertificatesListBytes(ModifiableByteArray certificatesListBytes) {
        this.certificatesListBytes = certificatesListBytes;
    }

    public void setCertificatesListBytes(byte[] array) {
        this.certificatesListBytes = ModifiableVariableFactory.safelySetValue(certificatesListBytes, array);
    }

    public List<CertificatePair> getCertificatesList() {
        return certificatesList;
    }

    public void setCertificatesList(List<CertificatePair> certificatesList) {
        this.certificatesList = certificatesList;
    }

    public void addCertificateList(CertificatePair CertificatePair) {
        if (this.certificatesList == null) {
            certificatesList = new LinkedList<>();
        }
        this.certificatesList.add(CertificatePair);
    }

    public ModifiableInteger getRequestContextLength() {
        return requestContextLength;
    }

    public void setRequestContextLength(ModifiableInteger requestContextLength) {
        this.requestContextLength = requestContextLength;
    }

    public void setRequestContextLength(int length) {
        this.requestContextLength = ModifiableVariableFactory.safelySetValue(requestContextLength, length);
    }

    public ModifiableByteArray getRequestContext() {
        return requestContext;
    }

    public void setRequestContext(ModifiableByteArray requestContext) {
        this.requestContext = requestContext;
    }

    public void setRequestContext(byte[] array) {
        this.requestContext = ModifiableVariableFactory.safelySetValue(requestContext, array);
    }

    public boolean hasRequestContext() {
        return requestContextLength.getValue() > 0;
    }

    private static byte[] encodeCert(Certificate cert) {
        ByteArrayOutputStream certByteStream = new ByteArrayOutputStream();
        try {
            cert.encode(certByteStream);
            return Arrays.copyOfRange(certByteStream.toByteArray(), HandshakeByteLength.CERTIFICATES_LENGTH
                    + HandshakeByteLength.CERTIFICATES_LENGTH, certByteStream.toByteArray().length);
        } catch (IOException ex) {
            throw new CryptoException(
                    "Cannot initialize CertificateMessage. An exception Occured while encoding the Certificates", ex);
        }

    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        if (certificatesListLength != null) {
            sb.append("\n  Certificates Length: ");
            sb.append(certificatesListLength.getValue());
        }
        if (certificatesListBytes != null) {
            sb.append("\n  Certificate:\n");
            sb.append(ArrayConverter.bytesToHexString(certificatesListBytes.getValue()));
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new CertificateHandler(context);
    }
}
