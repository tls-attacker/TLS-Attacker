/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.integration.handshakes;

import static org.junit.Assume.assumeNotNull;

import com.github.dockerjava.api.exception.DockerException;
import com.github.dockerjava.api.model.Image;
import de.rub.nds.tls.subject.ConnectionRole;
import de.rub.nds.tls.subject.TlsImplementationType;
import de.rub.nds.tls.subject.constants.TransportType;
import de.rub.nds.tls.subject.docker.DockerClientManager;
import de.rub.nds.tls.subject.docker.DockerTlsInstance;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory.TlsClientInstanceBuilder;
import de.rub.nds.tls.subject.docker.DockerTlsManagerFactory.TlsServerInstanceBuilder;
import de.rub.nds.tls.subject.docker.DockerTlsServerInstance;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.rub.nds.tlsattacker.util.FreePortFinder;
import java.security.Security;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import java.util.stream.Stream.Builder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@TestInstance(Lifecycle.PER_CLASS)
public abstract class AbstractHandshakeIT {

    private static final Integer PORT = FreePortFinder.getPossiblyFreePort();
    private static List<Image> localImages;

    private final TlsImplementationType implementation;
    private final TransportType transportType;
    private final ConnectionRole dockerConnectionRole;
    private final String version;
    private final String additionalParameters;

    private DockerTlsInstance dockerInstance;

    public AbstractHandshakeIT(
            TlsImplementationType implementation,
            ConnectionRole dockerConnectionRole,
            String version,
            String additionalParameters) {
        this.implementation = implementation;
        this.dockerConnectionRole = dockerConnectionRole;
        this.version = version;
        this.additionalParameters = additionalParameters;
        this.transportType = TransportType.TCP;
    }

    public AbstractHandshakeIT(
            TlsImplementationType implementation,
            ConnectionRole dockerConnectionRole,
            String version,
            String additionalParameters,
            TransportType transportType) {
        this.implementation = implementation;
        this.dockerConnectionRole = dockerConnectionRole;
        this.version = version;
        this.additionalParameters = additionalParameters;
        this.transportType = transportType;
    }

    @BeforeAll
    public void loadList() {
        try {
            DockerClientManager.getDockerClient().listContainersCmd().exec();
        } catch (Exception ex) {
            Assume.assumeNoException(ex);
        }
        localImages = DockerTlsManagerFactory.getAllImages();
    }

    @BeforeEach
    public final void setUp() throws InterruptedException {
        Security.addProvider(new BouncyCastleProvider());

        DockerClientManager.setDockerServerUsername(System.getenv("DOCKER_USERNAME"));
        DockerClientManager.setDockerServerPassword(System.getenv("DOCKER_PASSWORD"));

        prepareContainer();
    }

    private void prepareContainer() throws DockerException, InterruptedException {
        Image image =
                DockerTlsManagerFactory.getMatchingImage(
                        localImages, implementation, version, dockerConnectionRole);
        getDockerInstance(image);
    }

    private void getDockerInstance(Image image) throws DockerException, InterruptedException {
        if (dockerConnectionRole == ConnectionRole.SERVER) {
            TlsServerInstanceBuilder serverInstanceBuilder;
            if (image != null) {
                serverInstanceBuilder = new TlsServerInstanceBuilder(image, transportType);
            } else {
                serverInstanceBuilder =
                        new TlsServerInstanceBuilder(implementation, version, transportType).pull();
                localImages = DockerTlsManagerFactory.getAllImages();
                assumeNotNull(
                        image,
                        String.format(
                                "TLS implementation %s %s not available",
                                implementation.name(), version));
            }
            serverInstanceBuilder
                    .containerName("client-handshake-test-server-" + UUID.randomUUID())
                    .additionalParameters(additionalParameters);
            dockerInstance = serverInstanceBuilder.build();
            dockerInstance.start();
        } else {
            TlsClientInstanceBuilder clientInstanceBuilder;
            if (image != null) {
                clientInstanceBuilder = new TlsClientInstanceBuilder(image, transportType);
            } else {
                clientInstanceBuilder =
                        new TlsClientInstanceBuilder(implementation, version, transportType).pull();
                localImages = DockerTlsManagerFactory.getAllImages();
                assumeNotNull(
                        image,
                        String.format(
                                "TLS implementation %s %s not available",
                                implementation.name(), version));
            }
            clientInstanceBuilder
                    .containerName("server-handshake-test-client-" + UUID.randomUUID())
                    .ip("172.17.0.1")
                    .port(PORT)
                    .connectOnStartup(true)
                    .additionalParameters(additionalParameters);
            dockerInstance = clientInstanceBuilder.build();
        }
    }

    @ParameterizedTest
    @MethodSource("provideTestVectors")
    public final void testHandshakeSuccessfull(
            ProtocolVersion protocolVersion,
            NamedGroup namedGroup,
            CipherSuite cipherSuite,
            WorkflowTraceType workflowTraceType,
            boolean addEncryptThenMac,
            boolean addExtendedMasterSecret)
            throws InterruptedException {
        System.out.println(
                getParameterString(
                        protocolVersion,
                        namedGroup,
                        cipherSuite,
                        workflowTraceType,
                        addEncryptThenMac,
                        addExtendedMasterSecret));
        Config config = new Config();
        prepareConfig(
                cipherSuite,
                namedGroup,
                config,
                workflowTraceType,
                addExtendedMasterSecret,
                addEncryptThenMac,
                protocolVersion);

        State state = new State(config);
        WorkflowExecutor executor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        config.getWorkflowExecutorType(), state);
        setCallbacks(executor);

        executeTest(
                config,
                executor,
                state,
                protocolVersion,
                namedGroup,
                cipherSuite,
                workflowTraceType,
                addEncryptThenMac,
                addExtendedMasterSecret);
    }

    protected void executeTest(
            Config config,
            WorkflowExecutor executor,
            State state,
            ProtocolVersion protocolVersion,
            NamedGroup namedGroup,
            CipherSuite cipherSuite,
            WorkflowTraceType workflowTraceType,
            boolean addEncryptThenMac,
            boolean addExtendedMasterSecret)
            throws InterruptedException {

        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            try {
                executor.executeWorkflow();
            } catch (Exception ignored) {
                System.out.println(
                        "Encountered exception during handshake (" + ignored.getMessage() + ")");
            }
            if (!state.getWorkflowTrace().executedAsPlanned() && (i + 1) < MAX_ATTEMPTS) {
                System.out.println("Failed to complete handshake, reexecuting...");
                killContainer();
                prepareContainer();
                setConnectionTargetFields(config);
                state = new State(config);
                executor =
                        WorkflowExecutorFactory.createWorkflowExecutor(
                                config.getWorkflowExecutorType(), state);
                setCallbacks(executor);
            } else {
                return;
            }
        }

        failTest(
                state,
                protocolVersion,
                namedGroup,
                cipherSuite,
                workflowTraceType,
                addEncryptThenMac,
                addExtendedMasterSecret);
    }

    private static final int MAX_ATTEMPTS = 3;

    private void failTest(
            State state,
            ProtocolVersion protocolVersion,
            NamedGroup namedGroup,
            CipherSuite cipherSuite,
            WorkflowTraceType workflowTraceType,
            boolean addEncryptThenMac,
            boolean addExtendedMasterSecret) {
        System.out.println(state.getWorkflowTrace().toString());
        Assert.fail(
                "Failed to handshake with "
                        + implementation
                        + " parameters: "
                        + getParameterString(
                                protocolVersion,
                                namedGroup,
                                cipherSuite,
                                workflowTraceType,
                                addEncryptThenMac,
                                addExtendedMasterSecret));
    }

    public Stream<Arguments> provideTestVectors() {
        boolean[] addEncryptThenMacValues = getCryptoExtensionsValues();
        boolean[] addExtendedMasterSecretValues = getCryptoExtensionsValues();
        CipherSuite[] cipherSuites = getCipherSuitesToTest();
        NamedGroup[] namedGroups = getNamedGroupsToTest();
        ProtocolVersion[] protocolVersions = getProtocolVersionsToTest();
        WorkflowTraceType[] workflowTraceTypes = getWorkflowTraceTypesToTest();

        Builder<Arguments> builder = Stream.builder();
        for (boolean addEncryptThenMac : addEncryptThenMacValues) {
            for (boolean addExtendedMasterSecret : addExtendedMasterSecretValues) {
                for (CipherSuite cipherSuite : cipherSuites) {
                    for (NamedGroup namedGroup : namedGroups) {
                        for (ProtocolVersion protocolVersion : protocolVersions) {
                            for (WorkflowTraceType workflowTraceType : workflowTraceTypes) {
                                if (!cipherSuite.isSupportedInProtocol(protocolVersion)) {
                                    continue;
                                }
                                builder.add(
                                        Arguments.of(
                                                protocolVersion,
                                                namedGroup,
                                                cipherSuite,
                                                workflowTraceType,
                                                addEncryptThenMac,
                                                addExtendedMasterSecret));
                            }
                        }
                    }
                }
            }
        }
        return builder.build();
    }

    protected NamedGroup[] getNamedGroupsToTest() {
        return new NamedGroup[] {NamedGroup.SECP256R1};
    }

    protected ProtocolVersion[] getProtocolVersionsToTest() {
        return new ProtocolVersion[] {
            ProtocolVersion.TLS10, ProtocolVersion.TLS11, ProtocolVersion.TLS12
        };
    }

    protected CipherSuite[] getCipherSuitesToTest() {
        return new CipherSuite[] {
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
        };
    }

    protected WorkflowTraceType[] getWorkflowTraceTypesToTest() {
        return new WorkflowTraceType[] {
            WorkflowTraceType.HANDSHAKE, WorkflowTraceType.FULL_RESUMPTION
        };
    }

    protected boolean[] getCryptoExtensionsValues() {
        return new boolean[] {true, false};
    }

    protected void setCallbacks(WorkflowExecutor executor) {
        if (dockerConnectionRole == ConnectionRole.CLIENT) {
            executor.setBeforeTransportInitCallback(
                    (State tmpState) -> {
                        dockerInstance.start();
                        return 0;
                    });
        }
    }

    protected void prepareConfig(
            CipherSuite cipherSuite,
            NamedGroup namedGroup,
            Config config,
            WorkflowTraceType workflowTraceType,
            boolean addExtendedMasterSecret,
            boolean addEncryptThenMac,
            ProtocolVersion protocolVersion) {
        if (protocolVersion.isDTLS()) {
            config.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.UDP);
            config.getDefaultServerConnection().setTransportHandlerType(TransportHandlerType.UDP);
            config.setWorkflowExecutorType(WorkflowExecutorType.DTLS);
            config.setDefaultLayerConfiguration(LayerConfiguration.DTLS);
            config.setFinishWithCloseNotify(true);
            config.setIgnoreRetransmittedCssInDtls(true);
            config.setAddRetransmissionsToWorkflowTraceInDtls(false);
        }
        if (cipherSuite.isTLS13()
                || AlgorithmResolver.getKeyExchangeAlgorithm(cipherSuite).isEC()) {
            config.setAddECPointFormatExtension(Boolean.TRUE);
            config.setAddEllipticCurveExtension(Boolean.TRUE);
        } else {
            config.setAddECPointFormatExtension(Boolean.FALSE);
            config.setAddEllipticCurveExtension(Boolean.FALSE);
        }
        config.setWorkflowTraceType(workflowTraceType);
        if (cipherSuite.isTLS13()) {
            config.setAddExtendedMasterSecretExtension(false);
            config.setAddEncryptThenMacExtension(false);
            config.setAddSupportedVersionsExtension(true);
            config.setAddKeyShareExtension(true);
            if (workflowTraceType == WorkflowTraceType.FULL_TLS13_PSK
                    || workflowTraceType == WorkflowTraceType.FULL_ZERO_RTT) {
                config.setAddPSKKeyExchangeModesExtension(true);
                config.setAddPreSharedKeyExtension(true);
            }
            if (workflowTraceType == WorkflowTraceType.FULL_ZERO_RTT) {
                config.setAddEarlyDataExtension(true);
            }
        } else {
            config.setAddExtendedMasterSecretExtension(addExtendedMasterSecret);
            config.setAddEncryptThenMacExtension(addEncryptThenMac);
        }
        config.setDefaultClientSupportedCipherSuites(cipherSuite);
        config.setDefaultServerSupportedCipherSuites(cipherSuite);
        config.setDefaultSelectedCipherSuite(cipherSuite);
        config.setDefaultServerNamedGroups(namedGroup);
        config.setDefaultSelectedNamedGroup(namedGroup);
        config.setPreferredCertificateSignatureGroup(namedGroup);
        config.setDefaultEcCertificateCurve(namedGroup);
        config.setHighestProtocolVersion(protocolVersion);
        config.setDefaultSelectedProtocolVersion(protocolVersion);
        config.setSupportedVersions(protocolVersion);
        config.setRetryFailedClientTcpSocketInitialization(true);

        setConnectionTargetFields(config);
    }

    private void setConnectionTargetFields(Config config) {
        if (dockerConnectionRole == ConnectionRole.SERVER) {
            config.getDefaultClientConnection().setHostname("localhost");
            config.getDefaultClientConnection()
                    .setPort(((DockerTlsServerInstance) dockerInstance).getPort());
        } else {
            config.setDefaultRunningMode(RunningModeType.SERVER);
            config.getDefaultServerConnection().setHostname("server-handshake-test-host");
            config.getDefaultServerConnection().setPort(PORT);
            config.getDefaultServerConnection().setTimeout(1000);
        }
    }

    @AfterEach
    public void tearDown() {
        killContainer();
    }

    private void killContainer() {
        if (dockerInstance != null && dockerInstance.getId() != null) {
            dockerInstance.kill();
        }
    }

    private String getParameterString(
            ProtocolVersion protocolVersion,
            NamedGroup namedGroup,
            CipherSuite cipherSuite,
            WorkflowTraceType workflowTraceType,
            boolean addEncryptThenMac,
            boolean addExtendedMasterSecret) {
        return "PeerType="
                + dockerConnectionRole.name()
                + " Version="
                + protocolVersion
                + " NamedGroup="
                + namedGroup
                + " CipherSuite="
                + cipherSuite
                + " WorkflowTraceType="
                + workflowTraceType
                + " EncryptThenMac="
                + addEncryptThenMac
                + " ExtendedMasterSecert="
                + addExtendedMasterSecret;
    }
}
