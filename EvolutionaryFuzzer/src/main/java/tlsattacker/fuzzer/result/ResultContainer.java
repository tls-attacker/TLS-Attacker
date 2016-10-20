package tlsattacker.fuzzer.result;

import tlsattacker.fuzzer.analyzer.RuleAnalyzer;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import java.util.logging.Logger;

/**
 * This Class manages the BranchTraces and merges newly obtained Workflows with
 * the BranchTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ResultContainer {

    /**
     *
     */
    private static final Logger LOG = Logger.getLogger(ResultContainer.class.getName());

    /**
     * Singleton
     * 
     * @return Instance of the ResultContainer
     */
    public static ResultContainer getInstance() {
	return ResultContainerHolder.INSTANCE;
    }

    /**
     *
     */
    private EvolutionaryFuzzerConfig evolutionaryFuzzerConfig;

    /**
     *
     */
    private final RuleAnalyzer analyzer;

    /**
     *
     */
    private ResultContainer() {
	evolutionaryFuzzerConfig = tlsattacker.fuzzer.config.ConfigManager.getInstance().getConfig();
	analyzer = new RuleAnalyzer(evolutionaryFuzzerConfig);

    }

    /**
     * 
     * @param evolutionaryFuzzerConfig
     */
    public void setEvolutionaryFuzzerConfig(EvolutionaryFuzzerConfig evolutionaryFuzzerConfig) {
	this.evolutionaryFuzzerConfig = evolutionaryFuzzerConfig;
    }

    /**
     * 
     * @return
     */
    public RuleAnalyzer getAnalyzer() {
	return analyzer;
    }

    /**
     * 
     * @param r
     */
    public void commit(Result r) {
	analyzer.analyze(r);
    }

    // Singleton

    /**
     *
     */
    private static class ResultContainerHolder {

	/**
         *
         */
	private static final ResultContainer INSTANCE = new ResultContainer();

	/**
         *
         */
	private ResultContainerHolder() {
	}
    }
}
