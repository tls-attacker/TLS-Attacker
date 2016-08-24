package Result;

import Analyzer.Analyzer;
import Config.EvolutionaryFuzzerConfig;
import java.util.ArrayList;
import java.util.logging.Logger;
import TestVector.TestVector;

/**
 * This Class manages the BranchTraces and merges newly obtained Workflows with
 * the BranchTrace
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
public class ResultContainer {

    private static final Logger LOG = Logger.getLogger(ResultContainer.class.getName());

    /**
     * Singleton
     * 
     * @return Instance of the ResultContainer
     */
    public static ResultContainer getInstance() {
	return ResultContainerHolder.INSTANCE;
    }

    // List of old Results
    private ArrayList<TestVector> goodVectors;

    private EvolutionaryFuzzerConfig evolutionaryFuzzerConfig;

    public void setEvolutionaryFuzzerConfig(EvolutionaryFuzzerConfig evolutionaryFuzzerConfig) {
	this.evolutionaryFuzzerConfig = evolutionaryFuzzerConfig;
    }

    private int executed = 0;
    private Analyzer analyzer;

    private ResultContainer() {

	goodVectors = new ArrayList<>();

	evolutionaryFuzzerConfig = Config.ConfigManager.getInstance().getConfig();
	analyzer = new Analyzer(evolutionaryFuzzerConfig);

    }

    /**
     * Returns a list of WorkflowTraces that found new Branches or Vertices
     * 
     * @return ArrayList of good WorkflowTraces
     */
    public ArrayList<TestVector> getGoodVectors() {
	return goodVectors;
    }

    /**
     * Merges a Result with the BranchTrace and adds the Result to the
     * ResultList
     * 
     * @param result
     *            Result to be added in the Container
     */
    public void commit(Result result) {
	executed++;
	analyzer.analyze(result);

    }

    public int getExecuted() {
	return executed;
    }

    public void addGoodVector(TestVector vector) {
	goodVectors.add(vector);
    }

    public Analyzer getAnalyzer() {
	return analyzer;
    }

    // Singleton
    private static class ResultContainerHolder {

	private static final ResultContainer INSTANCE = new ResultContainer();

	private ResultContainerHolder() {
	}
    }
}
