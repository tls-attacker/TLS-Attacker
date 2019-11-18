/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.attacks.config.delegate.ProxyDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.*;

import java.util.LinkedList;
import java.util.List;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;

/**
 *
 */
public class Lucky13CommandConfig extends AttackConfig {

    public static final String ATTACK_COMMAND = "lucky13";

    @Parameter(names = "-measurements", description = "Number of timing measurement iterations")
    private Integer measurements = 100;

    @Parameter(names = "-mona_file", description = "File output for Mona timing lib. If set, the output is generated and written.")
    private String monaFile;

    @Parameter(names = "-mona_jar", description = "Location of the ReportingTool.jar file.")
    private String monaJar = "ReportingTool.jar";

    @Parameter(names = "-paddings", description = "Paddings to check for differences, column separated.")
    private String paddings = "0,255";

    @Parameter(names = "-blocks", description = "Number of blocks to encrypt (default is set to the value from the Lucky 13 paper, Section 3)")
    private Integer blocks = 18;

    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;
    @ParametersDelegate
    private ProxyDelegate proxyDelegate;

    /**
     *
     * @param delegate
     */
    public Lucky13CommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        starttlsDelegate = new StarttlsDelegate();
        proxyDelegate = new ProxyDelegate();
        addDelegate(clientDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(starttlsDelegate);
        addDelegate(proxyDelegate);
    }

    public Integer getMeasurements() {
        return measurements;
    }

    public void setMeasurements(Integer measurements) {
        this.measurements = measurements;
    }

    public String getMonaFile() {
        return monaFile;
    }

    public void setMonaFile(String monaFile) {
        this.monaFile = monaFile;
    }

    public String getMonaJar() {
        return monaJar;
    }

    public void setMonaJar(String monaJar) {
        this.monaJar = monaJar;
    }

    public String getPaddings() {
        return paddings;
    }

    public void setPaddings(String paddings) {
        this.paddings = paddings;
    }

    public Integer getBlocks() {
        return blocks;
    }

    public void setBlocks(Integer blocks) {
        this.blocks = blocks;
    }

    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return false;
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        if (ciphersuiteDelegate.getCipherSuites() == null) {
            /*
             * No explicit cipher suites are set. Use the default cipher suites
             * for this attack
             */
            List<CipherSuite> suiteList = new LinkedList<>();
            suiteList.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
            config.setDefaultServerSupportedCiphersuites(suiteList);
            config.setDefaultClientSupportedCiphersuites(suiteList);
            config.setDefaultSelectedCipherSuite(suiteList.get(0));
        }
        return config;
    }

}
