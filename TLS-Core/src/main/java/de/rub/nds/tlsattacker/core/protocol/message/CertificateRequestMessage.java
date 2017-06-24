/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.constants.ClientCertificateType;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.HashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.SignatureAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.handler.CertificateRequestHandler;
import de.rub.nds.tlsattacker.core.protocol.handler.ProtocolMessageHandler;
import de.rub.nds.tlsattacker.core.workflow.TlsConfig;
import de.rub.nds.tlsattacker.core.workflow.TlsContext;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Philip Riese <philip.riese@rub.de>
 */
@XmlRootElement
public class CertificateRequestMessage extends HandshakeMessage {

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.COUNT)
    private ModifiableInteger clientCertificateTypesCount;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray clientCertificateTypes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger signatureHashAlgorithmsLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray signatureHashAlgorithms;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger distinguishedNamesLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray distinguishedNames;

    public CertificateRequestMessage() {
        super(HandshakeMessageType.CERTIFICATE_REQUEST);
    }

    public CertificateRequestMessage(TlsConfig tlsConfig) {
        super(tlsConfig, HandshakeMessageType.CERTIFICATE_REQUEST);
    }

    public ModifiableInteger getClientCertificateTypesCount() {
        return clientCertificateTypesCount;
    }

    public void setClientCertificateTypesCount(ModifiableInteger clientCertificateTypesCount) {
        this.clientCertificateTypesCount = clientCertificateTypesCount;
    }

    public void setClientCertificateTypesCount(int clientCertificateTypesCount) {
        this.clientCertificateTypesCount = ModifiableVariableFactory.safelySetValue(this.clientCertificateTypesCount,
                clientCertificateTypesCount);
    }

    public ModifiableByteArray getClientCertificateTypes() {
        return clientCertificateTypes;
    }

    public void setClientCertificateTypes(ModifiableByteArray clientCertificateTypes) {
        this.clientCertificateTypes = clientCertificateTypes;
    }

    public void setClientCertificateTypes(byte[] clientCertificateTypes) {
        this.clientCertificateTypes = ModifiableVariableFactory.safelySetValue(this.clientCertificateTypes,
                clientCertificateTypes);
    }

    public ModifiableInteger getSignatureHashAlgorithmsLength() {
        return signatureHashAlgorithmsLength;
    }

    public void setSignatureHashAlgorithmsLength(ModifiableInteger signatureHashAlgorithmsLength) {
        this.signatureHashAlgorithmsLength = signatureHashAlgorithmsLength;
    }

    public void setSignatureHashAlgorithmsLength(int signatureHashAlgorithmsLength) {
        this.signatureHashAlgorithmsLength = ModifiableVariableFactory.safelySetValue(
                this.signatureHashAlgorithmsLength, signatureHashAlgorithmsLength);
    }

    public ModifiableByteArray getSignatureHashAlgorithms() {
        return signatureHashAlgorithms;
    }

    public void setSignatureHashAlgorithms(ModifiableByteArray signatureHashAlgorithms) {
        this.signatureHashAlgorithms = signatureHashAlgorithms;
    }

    public void setSignatureHashAlgorithms(byte[] signatureHashAlgorithms) {
        this.signatureHashAlgorithms = ModifiableVariableFactory.safelySetValue(this.signatureHashAlgorithms,
                signatureHashAlgorithms);
    }

    public ModifiableInteger getDistinguishedNamesLength() {
        return distinguishedNamesLength;
    }

    public void setDistinguishedNamesLength(ModifiableInteger distinguishedNamesLength) {
        this.distinguishedNamesLength = distinguishedNamesLength;
    }

    public void setDistinguishedNamesLength(int distinguishedNamesLength) {
        this.distinguishedNamesLength = ModifiableVariableFactory.safelySetValue(this.distinguishedNamesLength,
                distinguishedNamesLength);
    }

    public ModifiableByteArray getDistinguishedNames() {
        return distinguishedNames;
    }

    public void setDistinguishedNames(ModifiableByteArray distinguishedNames) {
        this.distinguishedNames = distinguishedNames;
    }

    public void setDistinguishedNames(byte[] distinguishedNames) {
        this.distinguishedNames = ModifiableVariableFactory.safelySetValue(this.distinguishedNames, distinguishedNames);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString());
        if (clientCertificateTypesCount != null) {
            sb.append("\n  Certificate Types Count: ").append(clientCertificateTypesCount.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Certificate Types: ");
        if (clientCertificateTypes != null) {
            for (int i = 0; i < clientCertificateTypes.getValue().length; i++) {
                sb.append(ClientCertificateType.getClientCertificateType(clientCertificateTypes.getValue()[i])).append(
                        ", ");
            }
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature Hash Algorithms Length: ");
        if (signatureHashAlgorithmsLength != null) {
            sb.append(signatureHashAlgorithmsLength.getValue());
        } else {
            sb.append("null");
        }
        sb.append("\n  Signature Hash Algorithms: ");
        if (signatureHashAlgorithms != null) {
            for (int i = 0; i < signatureHashAlgorithms.getValue().length / 2; i += 2) {
                sb.append(HashAlgorithm.getHashAlgorithm(signatureHashAlgorithms.getValue()[i])).append("-");
                sb.append(SignatureAlgorithm.getSignatureAlgorithm(signatureHashAlgorithms.getValue()[i + 1])).append(
                        ", ");
            }
        } else {
            sb.append("null");
        }
        if (distinguishedNamesLength != null) {
            sb.append("\n  Distinguished Names Length: ");
            sb.append(distinguishedNamesLength.getValue());
        }
        // sb.append("\n  Distinguished Names: ").append(ArrayConverter.bytesToHexString(distinguishedNames.getValue()));
        return sb.toString();
    }

    @Override
    public ProtocolMessageHandler getHandler(TlsContext context) {
        return new CertificateRequestHandler(context);
    }

}
