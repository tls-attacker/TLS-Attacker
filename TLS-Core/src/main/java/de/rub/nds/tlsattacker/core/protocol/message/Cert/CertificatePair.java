/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.core.protocol.message.Cert;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

/**
 * @author Nurullah Erinola <nurullah.erinola@rub.de>
 */
public class CertificatePair {

    private byte[] certificateConfig;
    private byte[] extensionsConfig;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray certificate;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger certificateLength;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.TLS_CONSTANT)
    private ModifiableByteArray extensions;

    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.LENGTH)
    private ModifiableInteger extensionsLength;

    public CertificatePair() {
    }

    public ModifiableByteArray getCertificate() {
        return certificate;
    }

    public void setCertificate(ModifiableByteArray certificate) {
        this.certificate = certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = ModifiableVariableFactory.safelySetValue(this.certificate, certificate);
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
        this.certificate = extensions;
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

    public byte[] getCertificateConfig() {
        return certificateConfig;
    }

    public void setCertificateConfig(byte[] certificateConfig) {
        this.certificateConfig = certificateConfig;
    }

    public byte[] getExtensionsConfig() {
        return extensionsConfig;
    }

    public void setExtensionsConfig(byte[] extensionsConfig) {
        this.extensionsConfig = extensionsConfig;
    }
}
