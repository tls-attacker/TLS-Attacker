/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import java.util.LinkedList;
import java.util.List;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;

@XmlAccessorType(XmlAccessType.FIELD)
public class CertificatePair extends ModifiableVariableHolder {

    private List<ExtensionMessage> extensionsConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray certificateBytes;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificateLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray extensions;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionsLength;

    private X509Certificate x509certificate;

    public CertificatePair() {
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
        this.certificateBytes = ModifiableVariableFactory.safelySetValue(this.certificateBytes, certificateBytes);
    }

    public ModifiableInteger getCertificateLength() {
        return certificateLength;
    }

    public void setCertificateLength(ModifiableInteger serverNameLength) {
        this.certificateLength = serverNameLength;
    }

    public void setCertificateLength(int certificateLength) {
        this.certificateLength = ModifiableVariableFactory.safelySetValue(this.certificateLength, certificateLength);
    }

    public ModifiableByteArray getExtensions() {
        return extensions;
    }

    public void setExtensions(ModifiableByteArray extensions) {
        this.certificateBytes = extensions;
    }

    public void setExtensions(byte[] extensions) {
        this.extensions = ModifiableVariableFactory.safelySetValue(this.extensions, extensions);
    }

    public ModifiableInteger getExtensionsLength() {
        return extensionsLength;
    }

    public void setExtensionsLength(ModifiableInteger extensionsLength) {
        this.extensionsLength = extensionsLength;
    }

    public void setExtensionsLength(int extensionsLength) {
        this.extensionsLength = ModifiableVariableFactory.safelySetValue(this.extensionsLength, extensionsLength);
    }

    public List<ExtensionMessage> getExtensionsConfig() {
        return extensionsConfig;
    }

    public void setExtensionsConfig(List<ExtensionMessage> extensionsConfig) {
        this.extensionsConfig = extensionsConfig;
    }

    public void addExtensionConfig(ExtensionMessage extension) {
        if (this.extensionsConfig == null) {
            extensionsConfig = new LinkedList<>();
        }
        this.extensionsConfig.add(extension);
    }
}
