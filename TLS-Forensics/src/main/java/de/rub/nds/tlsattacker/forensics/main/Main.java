/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsattacker.forensics.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.util.LogLevel;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.forensics.analyzer.ForensicAnalyzer;
import de.rub.nds.tlsattacker.forensics.config.TlsForensicsConfig;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class Main {

    protected static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(Main.class.getName());

    public static void main(String[] args) {
        TlsForensicsConfig config = new TlsForensicsConfig();
        JCommander commander = new JCommander(config);
        Exception ex = null;
        try {
            commander.parse(args);
            if (config.isDebug()) {
                Configurator.setRootLevel(org.apache.logging.log4j.Level.ALL);
            }
            // Cmd was parsable
            try {
                String workflowFile = config.getWorkflowInput();
                WorkflowTrace trace = WorkflowTraceSerializer.read(new FileInputStream(new File(workflowFile)));
                ForensicAnalyzer analyzer = new ForensicAnalyzer();
                BigInteger rsaPrivateKey = null;
                if (config.getKeyFile() != null) {
                    File keyFile = new File(config.getKeyFile());
                    if (keyFile.exists()) {
                        FileInputStream fileInputStream = new FileInputStream(keyFile);
                        InputStreamReader reader = new InputStreamReader(fileInputStream);
                        PEMParser parser = null;
                        try {
                            parser = new PEMParser(reader);
                            Object obj = parser.readObject();
                            if (obj instanceof PEMKeyPair) {
                                PEMKeyPair pair = (PEMKeyPair) obj;
                                obj = pair.getPrivateKeyInfo();
                            }
                            PrivateKeyInfo privKeyInfo = (PrivateKeyInfo) obj;
                            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
                            PrivateKey privateKey = converter.getPrivateKey(privKeyInfo);
                            if (privateKey instanceof RSAPrivateKey) {
                                rsaPrivateKey = ((RSAPrivateKey) privateKey).getPrivateExponent();
                                LOGGER.info("RSA privateKey:" + rsaPrivateKey.toString());
                            } else {
                                LOGGER.log(LogLevel.CONSOLE_OUTPUT,
                                        "PrivateKey file does not look like an RSA private key!");
                            }
                        } catch (Exception E) {
                            LOGGER.log(LogLevel.CONSOLE_OUTPUT, "Could not read private key");
                            E.printStackTrace();
                            return;
                        } finally {
                            if (parser != null) {
                                parser.close();
                            }
                            fileInputStream.close();
                            reader.close();
                        }
                    } else {
                        LOGGER.log(LogLevel.CONSOLE_OUTPUT, "PrivateKey file does not exist!");
                        return;
                    }
                }
                WorkflowTrace realWorkflowTrace = analyzer.getRealWorkflowTrace(trace, rsaPrivateKey);
                LOGGER.info("Provided WorkflowTrace:");
                LOGGER.info(trace.toString());
                LOGGER.info("Reconstructed WorkflowTrace:");
                LOGGER.info(realWorkflowTrace.toString());
            } catch (ConfigurationException E) {
                LOGGER.info("Encountered an Exception. Aborting.");
                LOGGER.debug(E);
            } catch (JAXBException | XMLStreamException | IOException ex1) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex1);
            }
        } catch (ParameterException E) {
            LOGGER.info("Could not parse provided parameters");
            LOGGER.debug(E);
            commander.usage();
            ex = E;
        }

    }
}
