/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.forensics.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.tlsattacker.forensics.analyzer.ForensicAnalyzer;
import de.rub.nds.tlsattacker.forensics.config.TlsForensicsConfig;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        TlsForensicsConfig config = new TlsForensicsConfig();
        JCommander commander = new JCommander(config);
        Exception ex = null;
        try {
            commander.parse(args);
            if (config.isDebug()) {
                Configurator.setRootLevel(org.apache.logging.log4j.Level.DEBUG);
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
                                CONSOLE.info("PrivateKey file does not look like an RSA private key!");
                            }
                        } catch (Exception E) {
                            CONSOLE.info("Could not read private key");
                            LOGGER.warn(E);
                            return;
                        } finally {
                            if (parser != null) {
                                parser.close();
                            }
                            fileInputStream.close();
                            reader.close();
                        }
                    } else {
                        CONSOLE.info("PrivateKey file does not exist!");
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
                LOGGER.warn(E);
            } catch (JAXBException | XMLStreamException | IOException ex1) {
                LOGGER.warn(ex1);
            }
        } catch (ParameterException E) {
            LOGGER.info("Could not parse provided parameters");
            LOGGER.debug(E);
            LOGGER.warn(E);
            commander.usage();
            ex = E;
        }

    }
}
