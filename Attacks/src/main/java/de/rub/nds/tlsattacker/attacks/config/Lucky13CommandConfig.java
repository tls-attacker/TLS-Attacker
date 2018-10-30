/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsattacker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.*;
import java.util.LinkedList;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;

/**
 *
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 * @author Malte Poll <malte.poll@rub.de>
 */
public class Lucky13CommandConfig extends AttackConfig {

    public static final String ATTACK_COMMAND = "lucky13";

    protected LinkedList<CipherSuite> cipherSuites;

    @Parameter(names = "-block_size", description = "Block size of the to be used block cipher")
    Integer blockSize = 16;

    @Parameter(names = "-measurements", description = "Number of timing measurement iterations")
    Integer measurements = 100;

    @Parameter(names = "-mona_file", description = "File output for Mona timing lib. If set, the output is generated and written.")
    String monaFile;

    @Parameter(names = "-paddings", description = "Paddings to check for differences, column separated.")
    String paddings = "0,255";

    @Parameter(names = "-blocks", description = "Number of blocks to encrypt (default is set to the value from the Lucky 13 paper, Section 3)")
    Integer blocks = 18;

    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private HostnameExtensionDelegate hostnameExtensionDelegate;
    @ParametersDelegate
    private CiphersuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    /**
     *
     * @param delegate
     */
    public Lucky13CommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        hostnameExtensionDelegate = new HostnameExtensionDelegate();
        ciphersuiteDelegate = new CiphersuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        starttlsDelegate = new StarttlsDelegate();
        addDelegate(clientDelegate);
        addDelegate(hostnameExtensionDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(starttlsDelegate);
        cipherSuites = new LinkedList<>();
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
    }

    public Integer getBlockSize() {
        return blockSize;
    }

    public void setBlockSize(Integer blockSize) {
        this.blockSize = blockSize;
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
        return config;
    }

}
