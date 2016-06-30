/**
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2016 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package tls.rub.evolutionaryfuzzer;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.tls.config.GeneralConfig;
import java.util.logging.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class Main {

    private static final Logger LOG = Logger.getLogger(Main.class.getName());

    /**
     *
     * @param args
     */
    public static void main(String args[]) {
        //TODO write a console interface
        GeneralConfig generalConfig = new GeneralConfig();

        EvolutionaryFuzzerConfig evoConfig = new EvolutionaryFuzzerConfig();
        JCommander jc = new JCommander(evoConfig);
        jc.addCommand(EvolutionaryFuzzerConfig.ATTACK_COMMAND, evoConfig);
        jc.parse(args);

        if (generalConfig.isHelp() || jc.getParsedCommand() == null) {
            jc.usage();
            return;
        }
        switch (jc.getParsedCommand()) {
            case EvolutionaryFuzzerConfig.ATTACK_COMMAND:
                Controller controller = new FuzzerController(evoConfig);
                controller.startFuzzer();
                break;
            default:
                jc.usage();
                return;
        }
    }
}
