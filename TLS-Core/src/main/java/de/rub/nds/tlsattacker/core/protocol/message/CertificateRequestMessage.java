/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAndHashAlgorithmsExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.CertificateRequestParser;
import de.rub.nds.tlsattacker.core.protocol.preparator.CertificateRequestPreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.CertificateRequestSerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlRootElement(name = "CertificateRequest")
public class CertificateRequestMessage extends HandshakeMessage<CertificateRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger clientCertificateTypesCount;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray clientCertificateTypes;

    // In TLS 1.3 this is moved to an extension
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureHashAlgorithmsLength;

    // In TLS 1.3 this is moved to an extension
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray signatureHashAlgorithms;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger distinguishedNamesLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray distinguishedNames;

    // TLS 1.3 only
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificateRequestContextLength;

    // TLS 1.3 only
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray certificateRequestContext;

    public CertificateRequestMessage() {
        super(HandshakeMessageType.CERTIFICATE_REQUEST);
    }

    public CertificateRequestMessage(Config tlsConfig) {
        super(HandshakeMessageType.CERTIFICATE_REQUEST);
        if (tlsConfig.getHighestProtocolVersion().isTLS13()) {
            this.setExtensions(new LinkedList<ExtensionMessage>());
            this.addExtension(new SignatureAndHashAlgorithmsExtensionMessage());
        }
        if (tlsConfig.isAddSignatureAlgorithmsCertExtension()) {
            addExtension(new SignatureAlgorithmsCertExtensionMessage());
        }
    }

    public ModifiableInteger getClientCertificateTypesCount() {
        return clientCertificateTypesCount;
    }

    public void setClientCertificateTypesCount(ModifiableInteger clientCertificateTypesCount) {
        this.clientCertificateTypesCount = clientCertificateTypesCount;
    }

    public void setClientCertificateTypesCount(int clientCertificateTypesCount) {
        this.clientCertificateTypesCount =
                ModifiableVariableFactory.safelySetValue(
                        this.clientCertificateTypesCount, clientCertificateTypesCount);
    }

    public ModifiableByteArray getClientCertificateTypes() {
        return clientCertificateTypes;
    }

    public void setClientCertificateTypes(ModifiableByteArray clientCertificateTypes) {
        this.clientCertificateTypes = clientCertificateTypes;
    }

    public void setClientCertificateTypes(byte[] clientCertificateTypes) {
        this.clientCertificateTypes =
                ModifiableVariableFactory.safelySetValue(
                        this.clientCertificateTypes, clientCertificateTypes);
    }

    public ModifiableInteger getSignatureHashAlgorithmsLength() {
        return signatureHashAlgorithmsLength;
    }

    public void setSignatureHashAlgorithmsLength(ModifiableInteger signatureHashAlgorithmsLength) {
        this.signatureHashAlgorithmsLength = signatureHashAlgorithmsLength;
    }

    public void setSignatureHashAlgorithmsLength(int signatureHashAlgorithmsLength) {
        this.signatureHashAlgorithmsLength =
                ModifiableVariableFactory.safelySetValue(
                        this.signatureHashAlgorithmsLength, signatureHashAlgorithmsLength);
    }

    public ModifiableByteArray getSignatureHashAlgorithms() {
        return signatureHashAlgorithms;
    }

    public void setSignatureHashAlgorithms(ModifiableByteArray signatureHashAlgorithms) {
        this.signatureHashAlgorithms = signatureHashAlgorithms;
    }

    public void setSignatureHashAlgorithms(byte[] signatureHashAlgorithms) {
        this.signatureHashAlgorithms =
                ModifiableVariableFactory.safelySetValue(
                        this.signatureHashAlgorithms, signatureHashAlgorithms);
    }

    public ModifiableInteger getDistinguishedNamesLength() {
        return distinguishedNamesLength;
    }

    public void setDistinguishedNamesLength(ModifiableInteger distinguishedNamesLength) {
        this.distinguishedNamesLength = distinguishedNamesLength;
    }

    public void setDistinguishedNamesLength(int distinguishedNamesLength) {
        this.distinguishedNamesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.distinguishedNamesLength, distinguishedNamesLength);
    }

    public ModifiableByteArray getDistinguishedNames() {
        return distinguishedNames;
    }

    public void setDistinguishedNames(ModifiableByteArray distinguishedNames) {
        this.distinguishedNames = distinguishedNames;
    }

    public void setDistinguishedNames(byte[] distinguishedNames) {
        this.distinguishedNames =
                ModifiableVariableFactory.safelySetValue(
                        this.distinguishedNames, distinguishedNames);
    }

    public ModifiableInteger getCertificateRequestContextLength() {
        return certificateRequestContextLength;
    }

    public void setCertificateRequestContextLength(
            ModifiableInteger certificateRequestContextLength) {
        this.certificateRequestContextLength = certificateRequestContextLength;
    }

    public void setCertificateRequestContextLength(int certificateRequestContextLength) {
        this.certificateRequestContextLength =
                ModifiableVariableFactory.safelySetValue(
                        this.certificateRequestContextLength, certificateRequestContextLength);
    }

    public ModifiableByteArray getCertificateRequestContext() {
        return certificateRequestContext;
    }

    public void setCertificateRequestContext(ModifiableByteArray certificateRequestContext) {
        this.certificateRequestContext = certificateRequestContext;
    }

    public void setCertificateRequestContext(byte[] certificateRequestContext) {
        this.certificateRequestContext =
                ModifiableVariableFactory.safelySetValue(
                        this.certificateRequestContext, certificateRequestContext);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("CertificateRequestMessage:");
        sb.append("\n  Certificate Types Count: ");
        if (clientCertificateTypesCount != null && clientCertificateTypesCount.getValue() != null) {
            sb.append(clientCertificateTypesCount.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Certificate Types: ");
        if (clientCertificateTypes != null && clientCertificateTypes.getValue() != null) {
            for (int i = 0; i < clientCertificateTypes.getValue().length; i++) {
                sb.append(
                                ClientCertificateType.getClientCertificateType(
                                        clientCertificateTypes.getValue()[i]))
                        .append(", ");
            }
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature Hash Algorithms Length: ");
        if (signatureHashAlgorithmsLength != null
                && signatureHashAlgorithmsLength.getValue() != null) {
            sb.append(signatureHashAlgorithmsLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature Hash Algorithms: ");
        if (signatureHashAlgorithms != null && signatureHashAlgorithms.getValue() != null) {
            try {
                List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms =
                        SignatureAndHashAlgorithm.getSignatureAndHashAlgorithms(
                                signatureHashAlgorithms.getValue());
                for (SignatureAndHashAlgorithm algo : signatureAndHashAlgorithms) {
                    sb.append(algo.name());
                }
            } catch (Exception e) {
                LOGGER.debug(e);
                LOGGER.debug(
                        "Signature and HashAlgorithms contain unparseable Algorithms: {}",
                        signatureHashAlgorithms);
            }
        } else {
            sb.append("null");
        }
        sb.append("\n  Distinguished Names Length: ");
        if (distinguishedNamesLength != null && distinguishedNamesLength.getValue() != null) {
            sb.append(distinguishedNamesLength.getValue());
        } else {
            sb.append("null");
        }
        // sb.append("\n Distinguished Names: ").append(ArrayConverter
        // .bytesToHexString(distinguishedNames.getValue()));
        return sb.toString();
    }

    @Override
    public String toShortString() {
        return "CR";
    }

    @Override
    public CertificateRequestHandler getHandler(TlsContext tlsContext) {
        return new CertificateRequestHandler(tlsContext);
    }

    @Override
    public CertificateRequestParser getParser(TlsContext tlsContext, InputStream stream) {
        return new CertificateRequestParser(stream, tlsContext);
    }

    @Override
    public CertificateRequestPreparator getPreparator(TlsContext tlsContext) {
        return new CertificateRequestPreparator(tlsContext.getChooser(), this);
    }

    @Override
    public CertificateRequestSerializer getSerializer(TlsContext tlsContext) {
        return new CertificateRequestSerializer(
                this, tlsContext.getChooser().getSelectedProtocolVersion());
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 61 * hash + Objects.hashCode(this.clientCertificateTypesCount);
        hash = 61 * hash + Objects.hashCode(this.clientCertificateTypes);
        hash = 61 * hash + Objects.hashCode(this.signatureHashAlgorithmsLength);
        hash = 61 * hash + Objects.hashCode(this.signatureHashAlgorithms);
        hash = 61 * hash + Objects.hashCode(this.distinguishedNamesLength);
        hash = 61 * hash + Objects.hashCode(this.distinguishedNames);
        hash = 61 * hash + Objects.hashCode(this.certificateRequestContextLength);
        hash = 61 * hash + Objects.hashCode(this.certificateRequestContext);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final CertificateRequestMessage other = (CertificateRequestMessage) obj;
        if (!Objects.equals(this.clientCertificateTypesCount, other.clientCertificateTypesCount)) {
            return false;
        }
        if (!Objects.equals(this.clientCertificateTypes, other.clientCertificateTypes)) {
            return false;
        }
        if (!Objects.equals(
                this.signatureHashAlgorithmsLength, other.signatureHashAlgorithmsLength)) {
            return false;
        }
        if (!Objects.equals(this.signatureHashAlgorithms, other.signatureHashAlgorithms)) {
            return false;
        }
        if (!Objects.equals(this.distinguishedNamesLength, other.distinguishedNamesLength)) {
            return false;
        }
        if (!Objects.equals(this.distinguishedNames, other.distinguishedNames)) {
            return false;
        }
        if (!Objects.equals(
                this.certificateRequestContextLength, other.certificateRequestContextLength)) {
            return false;
        }
        return Objects.equals(this.certificateRequestContext, other.certificateRequestContext);
    }
}
