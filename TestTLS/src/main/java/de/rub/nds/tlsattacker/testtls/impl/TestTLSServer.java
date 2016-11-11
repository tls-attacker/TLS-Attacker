/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.testtls.impl;

import de.rub.nds.tlsattacker.testtls.config.TestServerConfig;
import de.rub.nds.tlsattacker.testtls.policy.BotanPolicyParser;
import de.rub.nds.tlsattacker.testtls.policy.TlsPeerProperties;
import de.rub.nds.tlsattacker.tls.config.ConfigHandler;
import de.rub.nds.tlsattacker.tls.config.ConfigHandlerFactory;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import de.rub.nds.tlsattacker.tls.util.LogLevel;
import java.io.FileNotFoundException;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class TestTLSServer {

    public static Logger LOGGER = LogManager.getLogger(TestTLSServer.class);

    private final TestServerConfig testConfig;

    private ConfigHandler configHandler;

    private final GeneralConfig generalConfig;

    public TestTLSServer(TestServerConfig serverTestConfig, GeneralConfig generalConfig) {
        this.testConfig = serverTestConfig;
        this.generalConfig = generalConfig;
    }

    public boolean startTests() {
        configHandler = ConfigHandlerFactory.createConfigHandler("client");
        configHandler.initialize(generalConfig);

        List<TestTLS> tests = new LinkedList<>();
        TlsPeerProperties properties = new TlsPeerProperties();

        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Starting TLS Test");

        ProtocolVersionTest protocolVersionTest = new ProtocolVersionTest(configHandler, testConfig);
        protocolVersionTest.startTests();
        tests.add(protocolVersionTest);

        CryptoTest cryptoTest = new CryptoTest(configHandler, testConfig);
        cryptoTest.startTests();
        tests.add(cryptoTest);
        NamedCurvesTest ncTest = new NamedCurvesTest(configHandler, testConfig, cryptoTest.getSupportedCipherSuites());
        tests.add(ncTest);
        ncTest.startTests();
        SignatureAndHashAlgorithmsTest shTest = new SignatureAndHashAlgorithmsTest(configHandler, testConfig,
                cryptoTest.getSupportedCipherSuites());
        shTest.startTests();
        tests.add(shTest);

        CipherSuiteOrderTest csOrderTest = new CipherSuiteOrderTest(configHandler, testConfig);
        csOrderTest.startTests();
        tests.add(csOrderTest);
        // removing for now
        // AttacksTest attacks = new AttacksTest(configHandler, testConfig);
        // tests.add(attacks);
        // for (TestTLS test : tests) {
        // test.startTests();
        // }
        StringBuilder sb = new StringBuilder();
        for (TestTLS test : tests) {
            test.fillTlsPeerProperties(properties);
            sb.append("\n").append(test.getClass().getSimpleName()).append(test.getResult());
        }
        LOGGER.log(LogLevel.CONSOLE_OUTPUT, sb.toString());

        boolean policyCompliant = true;
        if (testConfig.getPolicy() != null) {
            BotanPolicyParser parser = new BotanPolicyParser();
            try {
                parser.parsePolicy(testConfig.getPolicy());
                TlsPeerProperties configuredProperties = parser.getTlsProperties();
                policyCompliant = properties.compliesPolicy(configuredProperties);
            } catch (FileNotFoundException ex) {
                LOGGER.error("Cannot find the provided file " + testConfig.getPolicy());
                LOGGER.info(ex.getLocalizedMessage(), ex);
                policyCompliant = false;
            }
        }

        return policyCompliant;
    }

}
