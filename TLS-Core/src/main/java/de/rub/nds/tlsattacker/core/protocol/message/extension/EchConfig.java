/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.message.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EchConfigVersion;
import de.rub.nds.tlsattacker.core.constants.EchVersion;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyDerivationFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyEncapsulationMechanism;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ech.HpkeCipherSuite;
import jakarta.xml.bind.annotation.*;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.Serializable;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

// supports all drafts
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class EchConfig implements Serializable {

    @XmlTransient private boolean isDefault = false;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] echConfigBytes;

    private EchConfigVersion configVersion;
    private int length;

    private int maximumNameLength;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)

    /** "publicName" in the standard. The domain responsible for updating the ECH Config for it. */
    private byte[] publicDomainName;

    @XmlElement(name = "extension")
    @XmlElementWrapper
    private List<ExtensionMessage> extensions = new LinkedList();

    // HPKE key data

    // only present from draft 11 and upwards
    private int configId;

    private HpkeKeyEncapsulationMechanism kem;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] hpkePublicKey;

    // ciphersuites from draft 7 and upwards
    @XmlElement(name = "hpkeCipherSuite")
    @XmlElementWrapper
    private List<HpkeCipherSuite> hpkeCipherSuites;

    // ciphersuites from draft 6
    @XmlElement(name = "cipherSuite")
    @XmlElementWrapper
    private List<CipherSuite> cipherSuites;

    // the Ech config of the TLS-Attacker, also a fallback for the client if a server does not offer
    // an ECH config
    public static EchConfig createDefaultEchConfig() {
        EchConfig echConfig = new EchConfig();
        echConfig.isDefault = true;
        echConfig.setEchConfigBytes(
                ArrayConverter.hexStringToByteArray(
                        "FE0D003AB8002000205611F61F4F5F5C801C60009DA68DD0EB0DD5DBA8FF33C32D5025D7FFADF5DC6F000400010001000B6578616D706C652E636F6D0000"));
        echConfig.setConfigVersion(EchVersion.DRAFT_14.getEchConfigVersion());
        echConfig.setLength(58);
        echConfig.setMaximumNameLength(0);
        // example.com
        echConfig.setPublicDomainName(
                ArrayConverter.hexStringToByteArray("6578616D706C652E636F6D"));
        echConfig.setExtensions(new LinkedList<>());
        echConfig.setConfigId(184);
        echConfig.setKem(HpkeKeyEncapsulationMechanism.DHKEM_X25519_HKDF_SHA256);
        echConfig.setHpkePublicKey(
                ArrayConverter.hexStringToByteArray(
                        "5611F61F4F5F5C801C60009DA68DD0EB0DD5DBA8FF33C32D5025D7FFADF5DC6F"));
        echConfig.setCipherSuites(new LinkedList<>());
        HpkeCipherSuite hpkeCipherSuite =
                new HpkeCipherSuite(
                        HpkeKeyDerivationFunction.HKDF_SHA256, HpkeAeadFunction.AES_128_GCM);
        echConfig.setHpkeCipherSuites(List.of(hpkeCipherSuite));
        return echConfig;
    }

    public boolean isDefault() {
        return isDefault;
    }

    public byte[] getEchConfigBytes() {
        return echConfigBytes;
    }

    public void setEchConfigBytes(byte[] echConfigBytes) {
        this.echConfigBytes = echConfigBytes;
    }

    public EchConfigVersion getConfigVersion() {
        return configVersion;
    }

    public void setConfigVersion(EchConfigVersion configVersion) {
        this.configVersion = configVersion;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public int getMaximumNameLength() {
        return maximumNameLength;
    }

    public void setMaximumNameLength(int maximumNameLength) {
        this.maximumNameLength = maximumNameLength;
    }

    public byte[] getPublicDomainName() {
        return publicDomainName;
    }

    public void setPublicDomainName(byte[] publicDomainName) {
        this.publicDomainName = publicDomainName;
    }

    public List<ExtensionMessage> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<ExtensionMessage> extensions) {
        this.extensions = extensions;
    }

    public int getConfigId() {
        return configId;
    }

    public void setConfigId(int configId) {
        this.configId = configId;
    }

    public HpkeKeyEncapsulationMechanism getKem() {
        return kem;
    }

    public void setKem(HpkeKeyEncapsulationMechanism kem) {
        this.kem = kem;
    }

    public byte[] getHpkePublicKey() {
        return hpkePublicKey;
    }

    public void setHpkePublicKey(byte[] hpkePublicKey) {
        this.hpkePublicKey = hpkePublicKey;
    }

    public List<HpkeCipherSuite> getHpkeCipherSuites() {
        return hpkeCipherSuites;
    }

    public void setHpkeCipherSuites(List<HpkeCipherSuite> hpkeCipherSuites) {
        this.hpkeCipherSuites = hpkeCipherSuites;
    }

    public List<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public HpkeAeadFunction getHpkeAeadFunction() {
        return hpkeCipherSuites.get(0).getAeadFunction();
    }

    public HpkeKeyDerivationFunction getHpkeKeyDerivationFunction() {
        return hpkeCipherSuites.get(0).getKeyDerivationFunction();
    }

    public void setCipherSuites(List<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        EchConfig echConfig = (EchConfig) o;
        return length == echConfig.length
                && maximumNameLength == echConfig.maximumNameLength
                && configId == echConfig.configId
                && Arrays.equals(echConfigBytes, echConfig.echConfigBytes)
                && configVersion == echConfig.configVersion
                && Arrays.equals(publicDomainName, echConfig.publicDomainName)
                && Objects.equals(extensions, echConfig.extensions)
                && kem == echConfig.kem
                && Arrays.equals(hpkePublicKey, echConfig.hpkePublicKey)
                && Objects.equals(hpkeCipherSuites, echConfig.hpkeCipherSuites)
                && Objects.equals(cipherSuites, echConfig.cipherSuites);
    }

    @Override
    public int hashCode() {
        int result =
                Objects.hash(
                        configVersion,
                        length,
                        maximumNameLength,
                        extensions,
                        configId,
                        kem,
                        hpkeCipherSuites,
                        cipherSuites);
        result = 31 * result + Arrays.hashCode(echConfigBytes);
        result = 31 * result + Arrays.hashCode(publicDomainName);
        result = 31 * result + Arrays.hashCode(hpkePublicKey);
        return result;
    }
}
