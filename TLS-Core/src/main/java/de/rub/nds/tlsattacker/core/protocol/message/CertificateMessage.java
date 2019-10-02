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
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificateEntry;
import de.rub.nds.tlsattacker.core.protocol.message.cert.CertificatePair;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.util.LinkedList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

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

    // this allows users to also send empty certificates
    @HoldsModifiableVariable
    @XmlElementWrapper
    @XmlElement(name = "certificatesList")
    private List<CertificatePair> certificatesList;

    @HoldsModifiableVariable
    private List<CertificateEntry> certificatesListAsEntry;

    @XmlTransient
    // TODO should this be transient?
    private CertificateKeyPair certificateKeyPair;

    public CertificateMessage() {
        super(HandshakeMessageType.CERTIFICATE);
    }

    public CertificateMessage(Config tlsConfig) {
        super(tlsConfig, HandshakeMessageType.CERTIFICATE);
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

    public List<CertificateEntry> getCertificatesListAsEntry() {
        return certificatesListAsEntry;
    }

    public void setCertificatesListAsEntry(List<CertificateEntry> certificatesListAsEntry) {
        this.certificatesListAsEntry = certificatesListAsEntry;
    }

    public void addCertificateList(CertificateEntry certificateEntry) {
        if (this.certificatesListAsEntry == null) {
            certificatesListAsEntry = new LinkedList<>();
        }
        this.certificatesListAsEntry.add(certificateEntry);
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

    public CertificateKeyPair getCertificateKeyPair() {
        return certificateKeyPair;
    }

    public void setCertificateKeyPair(CertificateKeyPair certificateKeyPair) {
        this.certificateKeyPair = certificateKeyPair;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("CertificateMessage:");
        sb.append("\n  Certificates Length: ");
        if (certificatesListLength != null && certificatesListLength.getValue() != null) {
            sb.append(certificatesListLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Certificate:\n");
        if (certificatesListBytes != null && certificatesListBytes.getValue() != null) {
            sb.append(ArrayConverter.bytesToHexString(certificatesListBytes.getValue()));
        } else {
            sb.append("null");
        }
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new CertificateMessageHandler(context);
    }
}
