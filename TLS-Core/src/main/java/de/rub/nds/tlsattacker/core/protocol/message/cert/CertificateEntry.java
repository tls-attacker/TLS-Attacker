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
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.io.ByteArrayInputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateEntry extends ModifiableVariableHolder {

    private static final Logger LOGGER = LogManager.getLogger();

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
    /** If explicit certifcate bytes should be used, they can be set here */
    private byte[] x509CerticiateConfig;

    public CertificateEntry() {}

    public CertificateEntry(byte[] x509CertificateConfig) {
        this.x509CerticiateConfig = x509CertificateConfig;
        // Try to set the x509 certificate
        try {
            X509Context context = new X509Context();
            X509Chooser chooser = context.getChooser();
            x509certificate = new X509Certificate("certificate");
            System.out.println("this");
            x509certificate
                    .getParser(chooser)
                    .parse(new ByteArrayInputStream(x509CerticiateConfig));
        } catch (Exception E) {
            LOGGER.warn("Could not parse a valid certificate from provided certificate bytes");
            x509certificate = null;
        }
    }

    public CertificateEntry(X509Certificate x509Certificate) {
        this.x509certificate = x509Certificate;
    }

    public byte[] getX509CerticiateConfig() {
        return x509CerticiateConfig;
    }

    public void setX509CerticiateConfig(byte[] x509CerticiateConfig) {
        this.x509CerticiateConfig = x509CerticiateConfig;
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
