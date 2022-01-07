/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsattacker.core.config;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@SuppressWarnings("SpellCheckingInspection")
public class ConfigTest {

    private Logger LOGGER = LogManager.getLogger();

    public ConfigTest() {
    }

    @Before
    public void setUp() {
    }

    /**
     * Updates the default_config.xml
     */
    @Test
    public void assertConfigInResourcesIsEqual() {
        ConfigIO.write(new Config(), new File("src/main/resources/default_config.xml"));
    }

    private void stripConfig(Config config) {
        Field[] declaredFields = config.getClass().getDeclaredFields();
        for (Field f : declaredFields) {
            try {
                if (!Modifier.isFinal(f.getModifiers())) {
                    f.setAccessible(true);
                    f.set(config, null);
                }
            } catch (IllegalArgumentException | IllegalAccessException ex) {
                LOGGER.error("Could not strip config from fields", ex);
            }
        }
    }

    /**
     * This and the following functions/tests generate all other configuration files in /resources/configs
     */
    @Test
    public void generateAppdataConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setDefaultApplicationMessageData("ayy lmao");
        writeToConfig(config, "appdata.config");
    }

    @Test
    public void generateConfigBlobConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setRecordLayerType(RecordLayerType.BLOB);
        writeToConfig(config, "config_blob.config");
    }

    @Test
    public void generateEcClientAuthenticationConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setClientAuthentication(true);

        ArrayList<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = new ArrayList<>();
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);

        config.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.ECDSA_SHA256);

        writeToConfig(config, "ec_clientAuthentication.config");
    }

    @Test
    public void generateEncryptThenMacConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setAddEncryptThenMacExtension(true);
        writeToConfig(config, "encryptThenMac.config");
    }

    @Test
    public void generateEnforceSettingsConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setEnforceSettings(true);
        writeToConfig(config, "enforceSettings.config");
    }

    @Test
    public void generateEsniServerConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setAddEncryptedServerNameIndicationExtension(true);

        KeyShareEntry keyShareEntry = new KeyShareEntry();

        keyShareEntry.setPrivateKey(
            new BigInteger("-35862849564059803287082945144062507860160501396022878289617408550825798132134"));

        ModifiableByteArray publicKey = new ModifiableByteArray();
        publicKey.setOriginalValue(
            ArrayConverter.hexStringToByteArray("2A981DB6CDD02A06C1763102C9E741365AC4E6F72B3176A6BD6A3523D3EC0F4C"));

        ModifiableByteArray group = new ModifiableByteArray();
        group.setOriginalValue(ArrayConverter.hexStringToByteArray("001D"));

        keyShareEntry.setGroup(group);
        keyShareEntry.setPublicKey(publicKey);
        ArrayList<KeyShareEntry> list = new ArrayList<>();
        list.add(keyShareEntry);

        config.setEsniServerKeyPairs(list);

        writeToConfig(config, "esniServer.config");
    }

    @Test
    public void generateExtendedMasterSecretConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setAddExtendedMasterSecretExtension(true);
        writeToConfig(config, "extended_master_secret.config");
    }

    @Test
    public void generateExtendedRandomConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setAddExtendedRandomExtension(true);
        writeToConfig(config, "extended_random.config");
    }

    @Test
    public void generateHeartbeatConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setAddHeartbeatExtension(true);
        writeToConfig(config, "heartbeat.config");
    }

    @Test
    public void generateHttpsConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setHttpsParsingEnabled(true);
        writeToConfig(config, "https.config");
    }

    @Test
    public void generatePskConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setDefaultPSKKey(ArrayConverter.hexStringToByteArray("AA"));
        writeToConfig(config, "psk.config");
    }

    @Test
    public void generatePwdConfig() {
        Config config = new Config();
        stripConfig(config);
        ArrayList<CipherSuite> clientSupportedCipherSuites = new ArrayList<>();
        clientSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        clientSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_256_GCM_SHA384);
        clientSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_128_CCM_SHA256);
        clientSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_256_CCM_SHA384);
        ArrayList<CipherSuite> serverSupportedCipherSuites = new ArrayList<>();
        serverSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        serverSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_256_GCM_SHA384);
        serverSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_128_CCM_SHA256);
        serverSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_256_CCM_SHA384);
        config.setDefaultClientSupportedCipherSuites(clientSupportedCipherSuites);
        config.setDefaultServerSupportedCipherSuites(serverSupportedCipherSuites);

        ArrayList<NamedGroup> defaultClientNamedGroups = new ArrayList<>();
        defaultClientNamedGroups.add(NamedGroup.BRAINPOOLP256R1);
        config.setDefaultClientNamedGroups(defaultClientNamedGroups);

        ArrayList<NamedGroup> defaultServerNamedGroups = new ArrayList<>();
        defaultServerNamedGroups.add(NamedGroup.BRAINPOOLP256R1);
        config.setDefaultServerNamedGroups(defaultServerNamedGroups);

        config.setDefaultSelectedNamedGroup(NamedGroup.BRAINPOOLP256R1);
        config.setAddPWDClearExtension(true);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        config.setAddKeyShareExtension(true);
        config.setUseFreshRandom(false);
        config.setDefaultClientRandom(
            ArrayConverter.hexStringToByteArray("528FBF52175DE2C869845FDBFA8344F7D732712EBFA679D8643CD31A880E043D"));
        config.setDefaultServerRandom(
            ArrayConverter.hexStringToByteArray("528FBF524378A1B13B8D2CBD247090721369F8BFA3CEEB3CFCD85CBFCDD58EAA"));
        config.setDefaultClientPWDUsername("fred");
        config.setDefaultPWDPassword("barney");
        config.setDefaultPWDIterations(40);
        config.setDefaultServerPWDPrivate(
            ArrayConverter.hexStringToByteArray("21D99D341C9797B3AE72DFD289971F1B74CE9DE68AD4B9ABF54888D8F6C5043C"));
        config.setDefaultServerPWDMask(
            ArrayConverter.hexStringToByteArray("0D96AB624D082C71255BE3648DCD303F6AB0CA61A95034A553E3308D1D3744E5"));
        config.setDefaultClientPWDPrivate(
            ArrayConverter.hexStringToByteArray("171DE8CAA5352D36EE96A39979B5B72FA189AE7A6A09C77F7B438AF16DF4A88B"));
        config.setDefaultClientPWDMask(
            ArrayConverter.hexStringToByteArray("4F745BDFC295D3B38429F7EB3025A48883728B07D88605C0EE202316A072D1BD"));
        config.setDefaultServerPWDSalt(
            ArrayConverter.hexStringToByteArray("963C77CDC13A2A8D75CDDDD1E0449929843711C21D47CE6E6383CDDA37E47DA3"));

        writeToConfig(config, "pwd.config");
    }

    @Test
    public void generatePwd13Config() {
        Config config = new Config();
        stripConfig(config);
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);
        config.setDefaultSelectedProtocolVersion(ProtocolVersion.TLS13);
        config.setTls13BackwardsCompatibilityMode(false);

        ArrayList<CipherSuite> clientSupportedCipherSuites = new ArrayList<>();
        clientSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        clientSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_256_GCM_SHA384);
        clientSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_128_CCM_SHA256);
        clientSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_256_CCM_SHA384);
        ArrayList<CipherSuite> serverSupportedCipherSuites = new ArrayList<>();
        serverSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        serverSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_256_GCM_SHA384);
        serverSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_128_CCM_SHA256);
        serverSupportedCipherSuites.add(CipherSuite.TLS_ECCPWD_WITH_AES_256_CCM_SHA384);
        config.setDefaultClientSupportedCipherSuites(clientSupportedCipherSuites);
        config.setDefaultServerSupportedCipherSuites(serverSupportedCipherSuites);

        ArrayList<NamedGroup> defaultClientNamedGroups = new ArrayList<>();
        defaultClientNamedGroups.add(NamedGroup.BRAINPOOLP256R1);
        config.setDefaultClientNamedGroups(defaultClientNamedGroups);

        ArrayList<NamedGroup> defaultServerNamedGroups = new ArrayList<>();
        defaultServerNamedGroups.add(NamedGroup.BRAINPOOLP256R1);
        config.setDefaultServerNamedGroups(defaultServerNamedGroups);

        config.setDefaultSelectedNamedGroup(NamedGroup.BRAINPOOLP256R1);
        config.setAddPWDClearExtension(true);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECCPWD_WITH_AES_128_GCM_SHA256);
        config.setAddKeyShareExtension(true);
        config.setUseFreshRandom(false);
        config.setDefaultClientRandom(
            ArrayConverter.hexStringToByteArray("528FBF52175DE2C869845FDBFA8344F7D732712EBFA679D8643CD31A880E043D"));
        config.setDefaultServerRandom(
            ArrayConverter.hexStringToByteArray("528FBF524378A1B13B8D2CBD247090721369F8BFA3CEEB3CFCD85CBFCDD58EAA"));
        config.setDefaultClientPWDUsername("fred");
        config.setDefaultPWDPassword("barney");
        config.setDefaultPWDIterations(40);
        config.setDefaultServerPWDPrivate(
            ArrayConverter.hexStringToByteArray("21D99D341C9797B3AE72DFD289971F1B74CE9DE68AD4B9ABF54888D8F6C5043C"));
        config.setDefaultServerPWDMask(
            ArrayConverter.hexStringToByteArray("0D96AB624D082C71255BE3648DCD303F6AB0CA61A95034A553E3308D1D3744E5"));
        config.setDefaultClientPWDPrivate(
            ArrayConverter.hexStringToByteArray("171DE8CAA5352D36EE96A39979B5B72FA189AE7A6A09C77F7B438AF16DF4A88B"));
        config.setDefaultClientPWDMask(
            ArrayConverter.hexStringToByteArray("4F745BDFC295D3B38429F7EB3025A48883728B07D88605C0EE202316A072D1BD"));
        config.setDefaultServerPWDSalt(
            ArrayConverter.hexStringToByteArray("963C77CDC13A2A8D75CDDDD1E0449929843711C21D47CE6E6383CDDA37E47DA3"));

        writeToConfig(config, "pwd13.config");
    }

    @Test
    public void generateRsaClientAuthenticationConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setClientAuthentication(true);

        ArrayList<SignatureAndHashAlgorithm> list = new ArrayList<>();
        list.add(SignatureAndHashAlgorithm.RSA_SHA256);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(list);

        config.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_SHA256);

        writeToConfig(config, "rsa_clientAuthentication.config");
    }

    @Test
    public void generateSniConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setAddServerNameIndicationExtension(true);
        writeToConfig(config, "sni.config");
    }

    @Test
    public void generateSrpConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setAddSRPExtension(true);
        config.setServerSendsApplicationData(true);
        writeToConfig(config, "srp.config");
    }

    @Test
    public void generateSSL2Config() {
        Config config = new Config();
        stripConfig(config);
        config.setHighestProtocolVersion(ProtocolVersion.SSL2);

        ArrayList<ProtocolVersion> protocolVersions = new ArrayList<>();
        protocolVersions.add(ProtocolVersion.SSL2);
        config.setSupportedVersions(protocolVersions);
        config.setWorkflowTraceType(WorkflowTraceType.SSL2_HELLO);

        writeToConfig(config, "ssl2.config");
    }

    @Test
    public void stripTracesConfig() {
        Config config = new Config();
        stripConfig(config);
        config.setResetWorkflowTracesBeforeSaving(true);
        writeToConfig(config, "stripTraces.config");
    }

    @Test
    public void generateTls13Config() {
        Config config = new Config();
        stripConfig(config);
        setUpBasicTls13Config(config);

        writeToConfig(config, "tls13.config");
    }

    @Test
    public void generateTls13ZeroRttConfig() {
        Config config = new Config();
        stripConfig(config);
        setUpBasicTls13Config(config);
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        config.setAddEarlyDataExtension(true);
        config.setSessionTicketLifetimeHint(3600);

        writeToConfig(config, "tls13zerortt.config");
    }

    private void setUpBasicTls13Config(Config config) {
        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);

        ArrayList<CipherSuite> clientSupportedCipherSuites = new ArrayList<>();
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        ArrayList<CipherSuite> serverSupportedCipherSuites = new ArrayList<>();
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        config.setDefaultClientSupportedCipherSuites(clientSupportedCipherSuites);
        config.setDefaultServerSupportedCipherSuites(serverSupportedCipherSuites);

        ArrayList<NamedGroup> defaultClientNamedGroups = new ArrayList<>();
        defaultClientNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultClientNamedGroups(defaultClientNamedGroups);

        ArrayList<NamedGroup> defaultServerNamedGroups = new ArrayList<>();
        defaultServerNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultServerNamedGroups(defaultServerNamedGroups);

        ArrayList<SignatureAndHashAlgorithm> clientSignatureAndHashAlgorithms = new ArrayList<>();
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(serverSignatureAndHashAlgorithms);

        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setDefaultClientKeyShareNamedGroups(NamedGroup.ECDH_X25519);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddRenegotiationInfoExtension(false);
    }

    @Test
    public void generateTls13EsniConfig() {
        Config config = new Config();
        stripConfig(config);

        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);

        ArrayList<CipherSuite> clientSupportedCipherSuites = new ArrayList<>();
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        ArrayList<CipherSuite> serverSupportedCipherSuites = new ArrayList<>();
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        config.setDefaultClientSupportedCipherSuites(clientSupportedCipherSuites);
        config.setDefaultServerSupportedCipherSuites(serverSupportedCipherSuites);

        ArrayList<NamedGroup> defaultClientNamedGroups = new ArrayList<>();
        defaultClientNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultClientNamedGroups(defaultClientNamedGroups);

        ArrayList<NamedGroup> defaultServerNamedGroups = new ArrayList<>();
        defaultServerNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultServerNamedGroups(defaultServerNamedGroups);

        ArrayList<SignatureAndHashAlgorithm> clientSignatureAndHashAlgorithms = new ArrayList<>();
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(serverSignatureAndHashAlgorithms);

        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddEncryptedServerNameIndicationExtension(true);
        config.setClientSupportedEsniNamedGroups(NamedGroup.ECDH_X25519);
        config.setClientSupportedEsniCipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256);

        writeToConfig(config, "tls13_esni.config");
    }

    @Test
    public void generateTls13SniConfig() {
        Config config = new Config();
        stripConfig(config);

        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);

        ArrayList<CipherSuite> clientSupportedCipherSuites = new ArrayList<>();
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        ArrayList<CipherSuite> serverSupportedCipherSuites = new ArrayList<>();
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        config.setDefaultClientSupportedCipherSuites(clientSupportedCipherSuites);
        config.setDefaultServerSupportedCipherSuites(serverSupportedCipherSuites);

        ArrayList<NamedGroup> defaultClientNamedGroups = new ArrayList<>();
        defaultClientNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultClientNamedGroups(defaultClientNamedGroups);

        ArrayList<NamedGroup> defaultServerNamedGroups = new ArrayList<>();
        defaultServerNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultServerNamedGroups(defaultServerNamedGroups);

        ArrayList<SignatureAndHashAlgorithm> clientSignatureAndHashAlgorithms = new ArrayList<>();
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(serverSignatureAndHashAlgorithms);

        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddServerNameIndicationExtension(true);
        writeToConfig(config, "tls13_sni.config");
    }

    @Test
    public void generateTlsX25519Config() {
        Config config = new Config();
        stripConfig(config);

        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);

        ArrayList<CipherSuite> clientSupportedCipherSuites = new ArrayList<>();
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        ArrayList<CipherSuite> serverSupportedCipherSuites = new ArrayList<>();
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        config.setDefaultClientSupportedCipherSuites(clientSupportedCipherSuites);
        config.setDefaultServerSupportedCipherSuites(serverSupportedCipherSuites);

        ArrayList<NamedGroup> defaultClientNamedGroups = new ArrayList<>();
        defaultClientNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultClientNamedGroups(defaultClientNamedGroups);

        ArrayList<NamedGroup> defaultServerNamedGroups = new ArrayList<>();
        defaultServerNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultServerNamedGroups(defaultServerNamedGroups);

        ArrayList<SignatureAndHashAlgorithm> clientSignatureAndHashAlgorithms = new ArrayList<>();
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(serverSignatureAndHashAlgorithms);

        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);

        writeToConfig(config, "tls13_x25519.config");
    }

    @Test
    public void generateTlsZeroRttConfig() {
        Config config = new Config();
        stripConfig(config);

        config.setHighestProtocolVersion(ProtocolVersion.TLS13);
        config.setSupportedVersions(ProtocolVersion.TLS13);

        ArrayList<CipherSuite> clientSupportedCipherSuites = new ArrayList<>();
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        clientSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        ArrayList<CipherSuite> serverSupportedCipherSuites = new ArrayList<>();
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        serverSupportedCipherSuites.add(CipherSuite.TLS_AES_256_GCM_SHA384);
        config.setDefaultClientSupportedCipherSuites(clientSupportedCipherSuites);
        config.setDefaultServerSupportedCipherSuites(serverSupportedCipherSuites);

        ArrayList<NamedGroup> defaultClientNamedGroups = new ArrayList<>();
        defaultClientNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultClientNamedGroups(defaultClientNamedGroups);

        ArrayList<NamedGroup> defaultServerNamedGroups = new ArrayList<>();
        defaultServerNamedGroups.add(NamedGroup.ECDH_X25519);
        config.setDefaultServerNamedGroups(defaultServerNamedGroups);

        ArrayList<SignatureAndHashAlgorithm> clientSignatureAndHashAlgorithms = new ArrayList<>();
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        clientSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_PSS_RSAE_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(serverSignatureAndHashAlgorithms);

        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        config.setAddEarlyDataExtension(true);
        config.setAddRenegotiationInfoExtension(false);
        config.setSessionTicketLifetimeHint(3600);

        writeToConfig(config, "tls13_x25519.config");
    }

    @Test
    public void generateTokenbindingConfig() {
        Config config = new Config();
        stripConfig(config);

        config.setAddTokenBindingExtension(true);
        config.setAddExtendedMasterSecretExtension(true);
        config.setAddRenegotiationInfoExtension(true);
        config.setHttpsParsingEnabled(true);

        writeToConfig(config, "tokenbinding.config");
    }

    private void writeToConfig(Config config, String configName) {
        try {
            JAXBContext context = JAXBContext.newInstance(Config.class);
            Marshaller m = context.createMarshaller();
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            // m.setProperty("com.sun.xml.internal.bind.xmlHeaders", "\n" + comment);
            m.marshal(config, new File("src/../../resources/configs/" + configName));
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

}
