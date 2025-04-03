/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsattacker.core.component.action;

import static org.junit.Assert.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.connection.InboundConnection;
import de.rub.nds.tlsattacker.core.connection.OutboundConnection;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.layer.constant.StackConfiguration;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.unittest.helper.FakeUdpTransportHandler;
import de.rub.nds.tlsattacker.core.workflow.DTLSWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import jakarta.xml.bind.DatatypeConverter;
import java.security.Security;
import java.util.List;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

/** Component test that covers forward actions in fragmented DTLS */
public class ForwardMessagesActionTest {
    
    private static final byte[] FRAGMENTED_DTLS_SERVER_FLIGHT =
            DatatypeConverter.parseHexBinary(
                    "16fefd0000000000000000006e020000620000000000000062fefdd824d690434ade425a8abe9c7f316317c3eaaf7951f464f7ef293fd0ff2761b320106cdf5af3ca3d93dad576852c72b86f0e94a4b1bc499f6601ed00a660f989fec02f00001aff01000100000b000403000102000e000500020001000017000016fefd000000000000000100780b0006b0000100000000006c0006ad0006aa308206a63082058ea00302010202104ce157a9b085e1bba0e5360de8150cac300d06092a864886f70d01010b050030818f310b3009060355040613024742311b30190603550408131247726561746572204d616e636865737465723110300e0603550407130716fefd000000000000000200f30b0006b0000100006c0000e753616c666f726431183016060355040a130f5365637469676f204c696d69746564313730350603550403132e5365637469676f2052534120446f6d61696e2056616c69646174696f6e2053656375726520536572766572204341301e170d3230303332363030303030305a170d3232303632383030303030305a30173115301306035504030c0c2a2e646973636f72642e676730820122300d06092a864886f70d01010105000382010f003082010a0282010100acb0e26a87ac77873e27f064b229b945bf1650d8f40c5f4a7a7ef0b787994c50c2591727727fb6450455f03c32b9a93bb7f66816fefd000000000000000300f30b0006b000010001530000e78b6eab5df48ac9fcb5aaf3b096b38b8b8e6e6c2d433dcb666a6257d9dc558e062d311da9f71db1153cf305c0a984effeee962a21cf9c29448fef188bf080af3ee96e4360f08ea5cca54509fc19272612465a5b7db199aac6b3d3032a2a7218f11cc49b82ff48a283767b20aca7c001bbdab46e9d90af637c0d1f9379cf00b91fa28de8f24329a298d8c4c3721c8e98a2f461bf088eda67ed869ff294809e076f59d5de888dad369e9a10589928cdf5c56b5fb0f48a65e3353c4b2eee9e33aa71492c7242f2162c14e9df75f3850203010001a38203733082036f301f0603551d2304183016801416fefd000000000000000400f30b0006b0000100023a0000e78d8c5ec454ad8ae177e99bf99b05e1b8018d61e1301d0603551d0e041604140bb9a50e045f7f9dc99f843a486aec4a3188ce4d300e0603551d0f0101ff0404030205a0300c0603551d130101ff04023000301d0603551d250416301406082b0601050507030106082b0601050507030230490603551d20044230403034060b2b06010401b231010202073025302306082b06010505070201161768747470733a2f2f7365637469676f2e636f6d2f4350533008060667810c01020130818406082b0601050507010104783076304f06082b060105050730028643687474703a2f2f6372742e736516fefd000000000000000500f30b0006b000010003210000e7637469676f2e636f6d2f5365637469676f525341446f6d61696e56616c69646174696f6e53656375726553657276657243412e637274302306082b060105050730018617687474703a2f2f6f6373702e7365637469676f2e636f6d30230603551d11041c301a820c2a2e646973636f72642e6767820a646973636f72642e6767308201f7060a2b06010401d679020402048201e7048201e301e100760046a555eb75fa912030b5a28969f4f37d112c4174befd49b885abf2fc70fe6d470000017119106cd0000004030047304502207ab714b20c75aa4013c2f7eb77742eab779a6106aa43a81916fefd000000000000000600f30b0006b000010004080000e74bfe56dd8a992192022100c5df5ffd1d88e3585b4a3f6a43855bc0067f6549e0c87dbb33596e7b4c624b59007600dfa55eab68824f1f6cadeeb85f4e3e5aeacda212a46a5e8e3b12c020445c2a730000017119106c9b0000040300473045022029593059c5d2d3efd4ba220fae07cf7662a9a6b41995ed93a731ea1e6a52ba20022100f51055b24374569e23d955d2d01ccc1a2b6aa1cafc137cc7aabe006ba5a97a9800760041c8cab1df22464a10c6a13a0942875e4e318b1b03ebeb4bc768f090629606f60000017119106ceb000004030047304502202a4f31f663e5c521beb54192e30a4416fefd000000000000000700f30b0006b000010004ef0000e7d4c6b407edb8e51d50add4531e163d943a022100dc8abe7accede3f0c6b3807c4056b281b64118757bef146b0221eb3c7943f33b0077006f5376ac31f03119d89900a45115ff77151c11d902c10029068db2089a37d9130000017119106c730000040300483046022100b32eca599ff57e0d367777b678f45138a238aefba267bfb495a23ba27fc70edb022100f5b2438ac1a27dc51349d29270e055a9b68c0216bf16d4793cb23898f2486c3d300d06092a864886f70d01010b0500038201010036aaa11f8f9c7c486ef3fb62ad27ce5f9b3e9b1f1ff9bb353ea072538276301fd61695ecb0b916fefd000000000000000800e60b0006b000010005d60000daa1e73f9917e5530b71d198ef5c6e9f70838f3587c6075b30f4c1c3dd6a5bcf974132a4f9e751866e94eca2017a2ca121b5562d684cd218a5f3dfa6f1f3acf0ed8ccf364caa6d9ccaa9986231b4e607b9fedcf021c47a349a37e5da88a4af4591c9881191298924bdfec09022d9916cb863711c28879e6e3bcea41c1da87018dca85285d5a43836f064440f1ab8fc47ac4920b56b7c10681443ca646b5e82ee067fcd06040fb68ff9804bec467b509818357dcd89fdc0e0d33e13a7791b67b7ba5c87fde38806c7e44cf7a3bc504761bd2caa0a9e7bbfaaac1b2416fefd000000000000000900f30c00012800020000000000e703001d2020138a9533c5711ba887b415978dd621a111e786dd4a9422c0e20cbbf21b667f080401007781e66836c77b3a290b6d485adf5c934957e1d0b363da506a078e741f9ab0a65fd811bb3673ec110a0fff86e9274cb22016ba0dea9c57a1e9c21ffe693e6b10a1672f2ee14d026a90c80036448e97207c0e0055cd24421386d411a8894a93943685b3dae788888e8ef56dda03293246fe6acd04b419385a44076a8eb7968fdf05a89dd0ac3f69a4cad93686651beaeba0496da6989600e50da457582252e7f94a48fe1dc3f9025678e64b062de714c65c7075e1bdaf58ce3a369fdc3f742a16fefd000000000000000a004d0c00012800020000e70000418c7579d1cbf140268046634ecd023bbc69c66a2d69cbea4e34beaa92a2d419b42b72a06a0841032047e75bc958e9dc8279fafe60f11d50cd66cb73a8562a17b0db16fefd000000000000000b003c0d0000300003000000000030030102400028040305030603080708080809080a080b080408050806040105010601030303010302040205020602000016fefd000000000000000c000c0e0000000004000000000000");
    // A single record, encapsulating multiple handshake messages
    private static final byte[] WHOLE_DTLS_SERVER_FLIGHT =
            DatatypeConverter.parseHexBinary(
                    "16fefd00000000000000000265020000600000000000000060fefd67e566a3eb06232c11140979c30325303b373c42037b68fd080e7067c311a63c20133e8f1e628484a2baaf7aa57c9bc51c08f0e53309b748d406a5ba4ee91cf311cca900001800170000ff01000100000b00020100000e000500020001000b00011f000100000000011f00011c000119308201153081bda003020102020900fbb765089b9eaee5300a06082a8648ce3d0403023011310f300d06035504030c06576562525443301e170d3235303332363134353432375a170d3235303432363134353432375a3011310f300d06035504030c065765625254433059301306072a8648ce3d020106082a8648ce3d03010703420004342b4063e99aaa1e8af9095c58be3feaeb89d86f9ceefb7b60c8a1d0ba9fe986ebde9cbca25692722d45a78949e3b2b091e8c7edb085630a9c9006591a6c2a7f300a06082a8648ce3d04030203470030440220439d3032df661e98b5f2c56e6fbaa07f78de6ea2800323725df8acaf7b36ef4e02200c9668e3ded1f3d6642ddb226af6dcc502ae0f576d6c3f85f0bd956d4e3a404b0c0000910002000000000091030017410411e9165ca618579f947bb77c48e8329087957ac83fb7239837cc9b56cf8cfc29c8abfccbead260845c533cbab3e71c380bd807f89709d24c6f528a50e04e4382040300483046022100a3908d19a34dd9a5cc080e8e4170aa90da03ae17173ffa23150ae3b033cd0fe8022100db25eb129925f94a1951eb0d581f8538956e32563f9e8d269b5bb5bfa66dbaf10d0000190003000000000019020140001204030804040105030805050108060601020100000e0000000004000000000000");

    private static final String SERVER_CTX_ALIAS = "serverctx";
    private static final String CLIENT_CTX_ALIAS = "clientctx";

    private final Config config;
    private FakeUdpTransportHandler serverTransportHandler;
    private FakeUdpTransportHandler clientTransportHandler;

    private final List<AliasedConnection> connectionList;

    public ForwardMessagesActionTest() {
        Security.addProvider(new BouncyCastleProvider());
        this.config = new Config();
        this.config.setDefaultLayerConfiguration(StackConfiguration.DTLS);
        this.config.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        this.config.setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS12);
        this.config.setInitialRecordVersion(ProtocolVersion.DTLS10);
        this.config.setIndividualTransportPacketsForFragments(true);
        InboundConnection serverConnection =
                new InboundConnection(SERVER_CTX_ALIAS, 0, "127.0.0.1");
        serverConnection.setTransportHandlerType(TransportHandlerType.UDP);
        serverConnection.setConnectionTimeout(0);
        serverConnection.setTimeout(0);
        OutboundConnection clientConnection =
                new OutboundConnection(CLIENT_CTX_ALIAS, 0, "127.0.0.1");
        clientConnection.setTransportHandlerType(TransportHandlerType.UDP);
        clientConnection.setConnectionTimeout(0);
        clientConnection.setTimeout(0);
        this.config.setDefaultServerConnection(serverConnection);
        this.config.setDefaultClientConnection(clientConnection);

        connectionList = List.of(serverConnection, clientConnection);
    }

    /**
     * Tests whether the ServerHello message in the server flight is received as planned via
     * ReceiveTillAction
     */
    @Test
    public void testBaselineProcessServerHello() {
        WorkflowTrace trace = new WorkflowTrace(connectionList);
        trace.addTlsAction(new ReceiveTillAction(SERVER_CTX_ALIAS, new ServerHelloMessage()));

        initAndExecute(trace, FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());

        initAndExecute(trace, WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    /**
     * Tests whether the Certificate message in the server flight is received as planned via
     * ReceiveTillAction
     */
    @Test
    public void testBaselineProcessCertificate() {
        WorkflowTrace trace = new WorkflowTrace(connectionList);
        trace.addTlsAction(new ReceiveTillAction(SERVER_CTX_ALIAS, new CertificateMessage()));

        initAndExecute(trace, FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());

        initAndExecute(trace, WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
    }

    /**
     * Tests whether the Certificate message in the server flight can be forwarded as planned via
     * TightForwardTillAction
     */
    @Test
    public void testBaselineTightForwardCertificate() {
        WorkflowTrace trace = new WorkflowTrace(connectionList);
        trace.addTlsAction(
                new TightForwardTillAction(
                        SERVER_CTX_ALIAS, CLIENT_CTX_ALIAS, new CertificateMessage()));

        initAndExecute(trace, FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertTrue(clientTransportHandler.getSentBytes().length > 0);

        initAndExecute(trace, WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertTrue(clientTransportHandler.getSentBytes().length > 0);
    }

    /**
     * Tests whether the ServerHello message in the server flight can be forwarded as planned via
     * TightForwardTillAction
     */
    @Test
    public void testBaselineTightForwardServerHello() {
        WorkflowTrace trace = new WorkflowTrace(connectionList);
        trace.addTlsAction(
                new TightForwardTillAction(
                        SERVER_CTX_ALIAS, CLIENT_CTX_ALIAS, new ServerHelloMessage()));

        initAndExecute(trace, FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertTrue(clientTransportHandler.getSentBytes().length > 0);

        initAndExecute(trace, WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertTrue(clientTransportHandler.getSentBytes().length > 0);
    }

    /**
     * Tests whether the ServerHello of the trace can be tightly forwarded and the certificate
     * message be received as planned
     */
    @Test
    public void testTightForwardAndProcessTrailing() {
        WorkflowTrace trace = new WorkflowTrace(connectionList);
        trace.addTlsAction(
                new TightForwardTillAction(
                        SERVER_CTX_ALIAS, CLIENT_CTX_ALIAS, new ServerHelloMessage()));
        trace.addTlsAction(
                new ReceiveAction(
                        SERVER_CTX_ALIAS,
                        new CertificateMessage(),
                        new ECDHEServerKeyExchangeMessage(),
                        new CertificateRequestMessage(),
                        new ServerHelloDoneMessage()));

        initAndExecute(trace, FRAGMENTED_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertTrue(clientTransportHandler.getSentBytes().length > 0);

        initAndExecute(trace, WHOLE_DTLS_SERVER_FLIGHT);

        assertTrue(trace.executedAsPlanned());
        assertTrue(trace.allActionsExecuted());
        assertTrue(clientTransportHandler.getSentBytes().length > 0);
    }

    private void initAndExecute(WorkflowTrace trace, byte[] serverFlight) {
        serverTransportHandler = new FakeUdpTransportHandler(ConnectionEndType.SERVER);
        clientTransportHandler = new FakeUdpTransportHandler(ConnectionEndType.CLIENT);
        serverTransportHandler.setFetchableByte(serverFlight);

        trace.reset();

        State state = new State(config, trace);

        state.getTlsContext(SERVER_CTX_ALIAS).setTransportHandler(serverTransportHandler);
        state.getTlsContext(CLIENT_CTX_ALIAS).setTransportHandler(clientTransportHandler);
        state.getConfig().setWorkflowExecutorShouldOpen(false);
        state.getConfig().setWorkflowExecutorShouldClose(false);

        new DTLSWorkflowExecutor(state).executeWorkflow();
    }
}
