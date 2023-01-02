/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.cert;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.tlsattacker.core.protocol.ModifiableVariableHolder;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.util.LinkedList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
public class CertificatePair extends ModifiableVariableHolder {

    private List<ExtensionMessage> extensionList;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray certificateBytes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificateLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray extensionBytes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionsLength;

    private X509Certificate x509certificate;

    public CertificatePair() {}

    public CertificatePair(X509Certificate x509Certificate) {
        this.x509certificate = x509Certificate;
    }

    public X509Certificate getX509certificate() {
        return x509certificate;
    }

    public void setX509certificate(X509Certificate x509certificate) {
        this.x509certificate = x509certificate;
    }

    public ModifiableByteArray getCertificateBytes() {
        return certificateBytes;
    }

    public void setCertificateBytes(ModifiableByteArray certificateBytes) {
        this.certificateBytes = certificateBytes;
    }

    public void setCertificateBytes(byte[] certificateBytes) {
        this.certificateBytes =
                ModifiableVariableFactory.safelySetValue(this.certificateBytes, certificateBytes);
    }

    public ModifiableInteger getCertificateLength() {
        return certificateLength;
    }

    public void setCertificateLength(ModifiableInteger serverNameLength) {
        this.certificateLength = serverNameLength;
    }

    public void setCertificateLength(int certificateLength) {
        this.certificateLength =
                ModifiableVariableFactory.safelySetValue(this.certificateLength, certificateLength);
    }

    public ModifiableByteArray getExtensionBytes() {
        return extensionBytes;
    }

    public void setExtensionBytes(ModifiableByteArray extensionBytes) {
        this.certificateBytes = extensionBytes;
    }

    public void setExtensionBytes(byte[] extensionBytes) {
        this.extensionBytes =
                ModifiableVariableFactory.safelySetValue(this.extensionBytes, extensionBytes);
    }

    public ModifiableInteger getExtensionsLength() {
        return extensionsLength;
    }

    public void setExtensionsLength(ModifiableInteger extensionsLength) {
        this.extensionsLength = extensionsLength;
    }

    public void setExtensionsLength(int extensionsLength) {
        this.extensionsLength =
                ModifiableVariableFactory.safelySetValue(this.extensionsLength, extensionsLength);
    }

    public List<ExtensionMessage> getExtensionList() {
        return extensionList;
    }

    public void setExtensionList(List<ExtensionMessage> extensionList) {
        this.extensionList = extensionList;
    }

    public void addExtension(ExtensionMessage extension) {
        if (this.extensionList == null) {
            extensionList = new LinkedList<>();
        }
        this.extensionList.add(extension);
    }
}
