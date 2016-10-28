package tlsattacker.fuzzer.result;

import tlsattacker.fuzzer.analyzer.RuleAnalyzer;
import tlsattacker.fuzzer.config.EvolutionaryFuzzerConfig;
import java.util.logging.Logger;
import tlsattacker.fuzzer.analyzer.Analyzer;

/**
 * This Class manages the BranchTraces and merges newly obtained Workflows with
 * the BranchTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@Deprecated
public class ResultContainer {
    /**
     * Singleton
     * 
     * @return Instance of the ResultContainer
     */
    public static ResultContainer getInstance() {
	return ResultContainerHolder.INSTANCE;
    }

    /**
     * Config to use
     */
    private EvolutionaryFuzzerConfig evolutionaryFuzzerConfig;

    /**
     * The Analyzer to use
     */
    private final Analyzer analyzer;

    private ResultContainer() {
	evolutionaryFuzzerConfig = tlsattacker.fuzzer.config.ConfigManager.getInstance().getConfig();
	analyzer = new RuleAnalyzer(evolutionaryFuzzerConfig);

    }

    public void setEvolutionaryFuzzerConfig(EvolutionaryFuzzerConfig evolutionaryFuzzerConfig) {
	this.evolutionaryFuzzerConfig = evolutionaryFuzzerConfig;
    }

    public Analyzer getAnalyzer() {
	return analyzer;
    }

    /**
     * Analyzes a Result
     * @param r Result to analyze
     */
    public void commit(Result r) {
	analyzer.analyze(r);
    }

    /**
     * Singleton
     */
    private static class ResultContainerHolder {

	/**
         * Singleton
         */
	private static final ResultContainer INSTANCE = new ResultContainer();

	private ResultContainerHolder() {
	}
    }

    private static final Logger LOG = Logger.getLogger(ResultContainer.class.getName());
}
