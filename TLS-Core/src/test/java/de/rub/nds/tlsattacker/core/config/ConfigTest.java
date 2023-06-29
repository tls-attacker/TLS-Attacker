/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
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
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.protocol.message.extension.keyshare.KeyShareEntry;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.ArrayList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ConfigTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final File RESOURCE_CONFIG_DIR = new File("src/../../resources/configs");

    private Config config;

    @BeforeEach
    public void setUp() {
        this.config = new Config();
        stripConfig(config);
    }

    /** Updates the default_config.xml */
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
     * This and the following functions/tests generate all other configuration files in
     * /resources/configs
     */
    @Test
    public void generateAppdataConfig() {
        config.setDefaultApplicationMessageData("ayy lmao");
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "appdata.config"));
    }

    @Test
    public void generateEcClientAuthenticationConfig() {
        config.setClientAuthentication(true);
        ArrayList<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = new ArrayList<>();
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        config.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.ECDSA_SHA256);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "ec_clientAuthentication.config"));
    }

    @Test
    public void generateEncryptThenMacConfig() {
        config.setAddEncryptThenMacExtension(true);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "encryptThenMac.config"));
    }

    @Test
    public void generateEnforceSettingsConfig() {
        config.setEnforceSettings(true);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "enforceSettings.config"));
    }

    @Test
    public void generateEsniServerConfig() {
        config.setAddEncryptedServerNameIndicationExtension(true);
        KeyShareEntry keyShareEntry = new KeyShareEntry();
        keyShareEntry.setPrivateKey(
                new BigInteger(
                        "-35862849564059803287082945144062507860160501396022878289617408550825798132134"));
        ModifiableByteArray publicKey = new ModifiableByteArray();
        publicKey.setOriginalValue(
                ArrayConverter.hexStringToByteArray(
                        "2A981DB6CDD02A06C1763102C9E741365AC4E6F72B3176A6BD6A3523D3EC0F4C"));
        ModifiableByteArray group = new ModifiableByteArray();
        group.setOriginalValue(ArrayConverter.hexStringToByteArray("001D"));
        keyShareEntry.setGroup(group);
        keyShareEntry.setPublicKey(publicKey);
        ArrayList<KeyShareEntry> list = new ArrayList<>();
        list.add(keyShareEntry);
        config.setEsniServerKeyPairs(list);
        config.setWorkflowExecutorType(WorkflowExecutorType.THREADED_SERVER);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "esniServer.config"));
    }

    /** Server that supports both ESNI and ECH client messages */
    @Test
    public void generateEsniEchServerConfig() {

        config.setAddEncryptedServerNameIndicationExtension(true);

        KeyShareEntry keyShareEntry = new KeyShareEntry();

        keyShareEntry.setPrivateKey(
                new BigInteger(
                        "-35862849564059803287082945144062507860160501396022878289617408550825798132134"));

        ModifiableByteArray publicKey = new ModifiableByteArray();
        publicKey.setOriginalValue(
                ArrayConverter.hexStringToByteArray(
                        "2A981DB6CDD02A06C1763102C9E741365AC4E6F72B3176A6BD6A3523D3EC0F4C"));

        ModifiableByteArray group = new ModifiableByteArray();
        group.setOriginalValue(ArrayConverter.hexStringToByteArray("001D"));

        keyShareEntry.setGroup(group);
        keyShareEntry.setPublicKey(publicKey);
        ArrayList<KeyShareEntry> list = new ArrayList<>();
        list.add(keyShareEntry);

        config.setEsniServerKeyPairs(list);

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
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                serverSignatureAndHashAlgorithms);

        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddEncryptedClientHelloExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setClientSupportedEsniNamedGroups(NamedGroup.ECDH_X25519);
        config.setClientSupportedEsniCipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256);
        config.setWorkflowExecutorType(WorkflowExecutorType.THREADED_SERVER);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "esniEchServer.config"));
    }

    @Test
    public void generateExtendedMasterSecretConfig() {
        config.setAddExtendedMasterSecretExtension(true);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "extended_master_secret.config"));
    }

    @Test
    public void generateExtendedRandomConfig() {
        config.setAddExtendedRandomExtension(true);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "extended_random.config"));
    }

    @Test
    public void generateHeartbeatConfig() {
        config.setAddHeartbeatExtension(true);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "heartbeat.config"));
    }

    @Test
    public void generateHttpsConfig() {
        config.setDefaultLayerConfiguration(LayerConfiguration.HTTPS);
        config.setWorkflowTraceType(WorkflowTraceType.DYNAMIC_HTTPS);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "https.config"));
    }

    @Test
    public void generatePskConfig() {
        config.setDefaultPSKKey(ArrayConverter.hexStringToByteArray("AA"));
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "psk.config"));
    }

    @Test
    public void generatePwdConfig() {
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
                ArrayConverter.hexStringToByteArray(
                        "528FBF52175DE2C869845FDBFA8344F7D732712EBFA679D8643CD31A880E043D"));
        config.setDefaultServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "528FBF524378A1B13B8D2CBD247090721369F8BFA3CEEB3CFCD85CBFCDD58EAA"));
        config.setDefaultClientPWDUsername("fred");
        config.setDefaultPWDPassword("barney");
        config.setDefaultPWDIterations(40);
        config.setDefaultServerPWDPrivate(
                ArrayConverter.hexStringToByteArray(
                        "21D99D341C9797B3AE72DFD289971F1B74CE9DE68AD4B9ABF54888D8F6C5043C"));
        config.setDefaultServerPWDMask(
                ArrayConverter.hexStringToByteArray(
                        "0D96AB624D082C71255BE3648DCD303F6AB0CA61A95034A553E3308D1D3744E5"));
        config.setDefaultClientPWDPrivate(
                ArrayConverter.hexStringToByteArray(
                        "171DE8CAA5352D36EE96A39979B5B72FA189AE7A6A09C77F7B438AF16DF4A88B"));
        config.setDefaultClientPWDMask(
                ArrayConverter.hexStringToByteArray(
                        "4F745BDFC295D3B38429F7EB3025A48883728B07D88605C0EE202316A072D1BD"));
        config.setDefaultServerPWDSalt(
                ArrayConverter.hexStringToByteArray(
                        "963C77CDC13A2A8D75CDDDD1E0449929843711C21D47CE6E6383CDDA37E47DA3"));

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "pwd.config"));
    }

    @Test
    public void generatePwd13Config() {
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
                ArrayConverter.hexStringToByteArray(
                        "528FBF52175DE2C869845FDBFA8344F7D732712EBFA679D8643CD31A880E043D"));
        config.setDefaultServerRandom(
                ArrayConverter.hexStringToByteArray(
                        "528FBF524378A1B13B8D2CBD247090721369F8BFA3CEEB3CFCD85CBFCDD58EAA"));
        config.setDefaultClientPWDUsername("fred");
        config.setDefaultPWDPassword("barney");
        config.setDefaultPWDIterations(40);
        config.setDefaultServerPWDPrivate(
                ArrayConverter.hexStringToByteArray(
                        "21D99D341C9797B3AE72DFD289971F1B74CE9DE68AD4B9ABF54888D8F6C5043C"));
        config.setDefaultServerPWDMask(
                ArrayConverter.hexStringToByteArray(
                        "0D96AB624D082C71255BE3648DCD303F6AB0CA61A95034A553E3308D1D3744E5"));
        config.setDefaultClientPWDPrivate(
                ArrayConverter.hexStringToByteArray(
                        "171DE8CAA5352D36EE96A39979B5B72FA189AE7A6A09C77F7B438AF16DF4A88B"));
        config.setDefaultClientPWDMask(
                ArrayConverter.hexStringToByteArray(
                        "4F745BDFC295D3B38429F7EB3025A48883728B07D88605C0EE202316A072D1BD"));
        config.setDefaultServerPWDSalt(
                ArrayConverter.hexStringToByteArray(
                        "963C77CDC13A2A8D75CDDDD1E0449929843711C21D47CE6E6383CDDA37E47DA3"));

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "pwd13.config"));
    }

    @Test
    public void generateRsaClientAuthenticationConfig() {
        config.setClientAuthentication(true);
        ArrayList<SignatureAndHashAlgorithm> list = new ArrayList<>();
        list.add(SignatureAndHashAlgorithm.RSA_SHA256);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(list);
        config.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_SHA256);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "rsa_clientAuthentication.config"));
    }

    @Test
    public void generateSniConfig() {
        config.setAddServerNameIndicationExtension(true);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "sni.config"));
    }

    @Test
    public void generateSrpConfig() {
        config.setAddSRPExtension(true);
        config.setServerSendsApplicationData(true);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "srp.config"));
    }

    @Test
    public void generateSSL2Config() {
        config.setHighestProtocolVersion(ProtocolVersion.SSL2);
        config.setDefaultLayerConfiguration(LayerConfiguration.SSL2);
        ArrayList<ProtocolVersion> protocolVersions = new ArrayList<>();
        protocolVersions.add(ProtocolVersion.SSL2);
        config.setSupportedVersions(protocolVersions);
        config.setWorkflowTraceType(WorkflowTraceType.SSL2_HELLO);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "ssl2.config"));
    }

    @Test
    public void stripTracesConfig() {
        config.setResetWorkflowTracesBeforeSaving(true);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "stripTraces.config"));
    }

    @Test
    public void generateTls13Config() {
        setUpBasicTls13Config(config);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "tls13.config"));
    }

    @Test
    public void generateTls13ZeroRttConfig() {
        setUpBasicTls13Config(config);
        config.setAddPSKKeyExchangeModesExtension(true);
        config.setAddPreSharedKeyExtension(true);
        config.setAddEarlyDataExtension(true);
        config.setSessionTicketLifetimeHint(3600);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "tls13zerortt.config"));
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
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                clientSignatureAndHashAlgorithms);

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
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                serverSignatureAndHashAlgorithms);

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
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                serverSignatureAndHashAlgorithms);

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

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "tls13_esni.config"));
    }

    @Test
    public void generateTls13EchConfigs() {
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
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                serverSignatureAndHashAlgorithms);

        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddEncryptedClientHelloExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setClientSupportedEsniNamedGroups(NamedGroup.ECDH_X25519);
        config.setClientSupportedEsniCipherSuites(CipherSuite.TLS_AES_128_GCM_SHA256);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "tls13_ech.config"));

        config.setWorkflowExecutorType(WorkflowExecutorType.THREADED_SERVER);
    }

    @Test
    public void generateTls13SniConfig() {
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
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                serverSignatureAndHashAlgorithms);

        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);
        config.setAddServerNameIndicationExtension(true);
        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "tls13_sni.config"));
    }

    @Test
    public void generateTlsX25519Config() {
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
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                clientSignatureAndHashAlgorithms);

        ArrayList<SignatureAndHashAlgorithm> serverSignatureAndHashAlgorithms = new ArrayList<>();
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        serverSignatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                serverSignatureAndHashAlgorithms);

        config.setDefaultSelectedNamedGroup(NamedGroup.ECDH_X25519);
        config.setDefaultSelectedCipherSuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddSupportedVersionsExtension(true);
        config.setAddKeyShareExtension(true);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "tls13_x25519.config"));
    }

    @Test
    public void generateTlsZeroRttConfig() {
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
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(
                clientSignatureAndHashAlgorithms);

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
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(
                serverSignatureAndHashAlgorithms);

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

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "tls_zerortt.config"));
    }

    @Test
    public void generateTokenbindingConfig() {
        config.setAddTokenBindingExtension(true);
        config.setAddExtendedMasterSecretExtension(true);
        config.setAddRenegotiationInfoExtension(true);

        ConfigIO.write(config, new File(RESOURCE_CONFIG_DIR, "tokenbinding.config"));
    }
}
