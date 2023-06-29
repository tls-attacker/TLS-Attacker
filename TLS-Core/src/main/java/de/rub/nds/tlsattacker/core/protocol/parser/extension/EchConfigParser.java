/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.protocol.parser.extension;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.EchConfigVersion;
import de.rub.nds.tlsattacker.core.constants.ExtensionByteLength;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeAeadFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyDerivationFunction;
import de.rub.nds.tlsattacker.core.constants.hpke.HpkeKeyEncapsulationMechanism;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.layer.data.Parser;
import de.rub.nds.tlsattacker.core.protocol.message.extension.EchConfig;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ech.HpkeCipherSuite;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EchConfigParser extends Parser<List<EchConfig>> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final TlsContext tlsContext;

    public EchConfigParser(InputStream inputStream, TlsContext tlsContext) {
        super(inputStream);
        this.tlsContext = tlsContext;
    }

    @Override
    public void parse(List<EchConfig> echConfigs) {

        // parse length of all following ech configs
        int configsLength = this.parseIntField(ExtensionByteLength.ECH_CONFIG_LIST_LENGTH);

        // ignore two length bytes
        int configBytesStart = ExtensionByteLength.ECH_CONFIG_LIST_LENGTH;

        while (getAlreadyParsed().length < configsLength) {
            EchConfig echConfig = new EchConfig();
            try {
                parseVersion(echConfig);
                parseLength(echConfig);
                parseEchContents(echConfig);
                echConfig.setEchConfigBytes(
                        Arrays.copyOfRange(
                                getAlreadyParsed(), configBytesStart, getAlreadyParsed().length));
                echConfigs.add(echConfig);
                configBytesStart += getAlreadyParsed().length;
            } catch (ParserException e) {
                LOGGER.warn("Error during EchConfig parsing: ", e);
            }
        }
    }

    private void parseVersion(EchConfig echConfig) {
        byte[] version = this.parseByteArrayField(ExtensionByteLength.ESNI_RECORD_VERSION);
        echConfig.setConfigVersion(EchConfigVersion.getEnumByByte(version));
        LOGGER.debug("Version: " + echConfig.getConfigVersion());
    }

    private void parseLength(EchConfig echConfig) {
        int length = this.parseIntField(ExtensionByteLength.ECH_CONFIG_LENGTH);
        echConfig.setLength(length);
        LOGGER.debug("Length: " + echConfig.getLength());
    }

    private void parseEchContents(EchConfig echConfig) {
        switch (echConfig.getConfigVersion()) {
            case DRAFT_FF03:
                parsePublicName(echConfig, false);
                parsePublicKey(echConfig);
                parseKemId(echConfig);
                parseCipherSuites(echConfig);
                parseMaximumNameLength(echConfig);
                parseExtensions(echConfig);
                break;
            case DRAFT_FF07:
            case DRAFT_FF08:
            case DRAFT_FF09:
                parsePublicName(echConfig, false);
                parsePublicKey(echConfig);
                parseKemId(echConfig);
                parseHPKECipherSuites(echConfig);
                parseMaximumNameLength(echConfig);
                parseExtensions(echConfig);
                break;
                // this case is slightly broken in the RFC, the same version byte refers to two
                // different EchConfig versions
                // we interpret it as the newer one here
            case DRAFT_FF0A:
            case DRAFT_FF0B:
            case DRAFT_FF0C:
            case DRAFT_FF0D:
                parseHpkeKeyConfig(echConfig);
                parseMaximumNameLength(echConfig);
                parsePublicName(echConfig, true);
                parseExtensions(echConfig);
                break;
        }
    }

    private void parseMaximumNameLength(EchConfig echConfig) {
        int length = this.parseIntField(ExtensionByteLength.ECH_CONFIG_MAX_NAME_LENGTH);
        echConfig.setMaximumNameLength(length);
        LOGGER.debug("Maximum Name Length: " + echConfig.getMaximumNameLength());
    }

    private void parsePublicName(EchConfig echConfig, boolean parseShort) {
        int publicNameLen;
        if (parseShort) {
            publicNameLen = this.parseIntField(ExtensionByteLength.ECH_CONFIG_PUBLIC_NAME);
        } else {
            publicNameLen = this.parseIntField(ExtensionByteLength.ECH_CONFIG_PUBLIC_NAME_LONG);
        }
        byte[] publicName = this.parseByteArrayField(publicNameLen);
        echConfig.setPublicDomainName(publicName);
        LOGGER.debug(
                "Public Name: " + ArrayConverter.bytesToHexString(echConfig.getPublicDomainName()));
    }

    private void parseExtensions(EchConfig echConfig) {
        int extensionsLength = this.parseIntField(HandshakeByteLength.EXTENSION_LENGTH);

        byte[] extensionBytes = parseByteArrayField(extensionsLength);

        ByteArrayInputStream innerStream = new ByteArrayInputStream(extensionBytes);
        ExtensionListParser parser = new ExtensionListParser(innerStream, tlsContext, false);
        List<ExtensionMessage> extensionMessages = new LinkedList<>();
        parser.parse(extensionMessages);
        echConfig.getExtensions().addAll(extensionMessages);
    }

    private void parseHpkeKeyConfig(EchConfig echConfig) {
        parseConfigId(echConfig);
        parseKemId(echConfig);
        parsePublicKey(echConfig);
        parseHPKECipherSuites(echConfig);
    }

    private void parseConfigId(EchConfig echConfig) {
        int configId = this.parseIntField(ExtensionByteLength.ECH_CONFIG_ID);
        echConfig.setConfigId(configId);
        LOGGER.debug("Config ID: " + echConfig.getConfigId());
    }

    private void parseKemId(EchConfig echConfig) {
        byte[] kemId = this.parseByteArrayField(ExtensionByteLength.ECH_CONFIG_KEM_ID);
        HpkeKeyEncapsulationMechanism kem = HpkeKeyEncapsulationMechanism.getEnumByByte(kemId);
        echConfig.setKem(kem);
        LOGGER.debug("KEM ID: " + echConfig.getKem());
    }

    private void parsePublicKey(EchConfig echConfig) {
        int publicKeyLen = this.parseIntField(ExtensionByteLength.ECH_CONFIG_PUBLIC_KEY);
        byte[] publicKey = this.parseByteArrayField(publicKeyLen);
        echConfig.setHpkePublicKey(publicKey);
        LOGGER.debug(
                "Public Key: " + ArrayConverter.bytesToHexString(echConfig.getHpkePublicKey()));
    }

    private void parseHPKECipherSuites(EchConfig echConfig) {
        int ciphersuitesLen = this.parseIntField(ExtensionByteLength.ECH_CONFIG_CIPHERSUITES);
        int i = 0;
        List<HpkeCipherSuite> hpkeCipherSuites = new LinkedList<>();
        while (i < ciphersuitesLen) {
            HpkeKeyDerivationFunction hkdfAlgorithm = parseKdfId();
            HpkeAeadFunction aeadAlgorithm = parseAEADId();
            hpkeCipherSuites.add(new HpkeCipherSuite(hkdfAlgorithm, aeadAlgorithm));
            i += (ExtensionByteLength.ECH_CONFIG_KDF_ID + ExtensionByteLength.ECH_CONFIG_AEAD_ID);
        }
        echConfig.setHpkeCipherSuites(hpkeCipherSuites);
    }

    private HpkeKeyDerivationFunction parseKdfId() {
        byte[] kdfId = this.parseByteArrayField(ExtensionByteLength.ECH_CONFIG_KDF_ID);
        return HpkeKeyDerivationFunction.getEnumByByte(kdfId);
    }

    private HpkeAeadFunction parseAEADId() {
        byte[] aeadId = this.parseByteArrayField(ExtensionByteLength.ECH_CONFIG_AEAD_ID);
        return HpkeAeadFunction.getEnumByByte(aeadId);
    }

    private void parseCipherSuites(EchConfig echConfig) {
        int cipherSuitesLen = this.parseIntField(HandshakeByteLength.CIPHER_SUITES_LENGTH);
        byte[] cipherSuitesBytes = this.parseByteArrayField(cipherSuitesLen);
        List<CipherSuite> cipherSuites = CipherSuite.getCipherSuites(cipherSuitesBytes);
        echConfig.setCipherSuites(cipherSuites);
    }
}
