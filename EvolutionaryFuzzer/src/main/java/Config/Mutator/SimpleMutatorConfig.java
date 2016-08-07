package Config.Mutator;

import Config.*;
import Server.TLSServer;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.validators.PositiveInteger;
import de.rub.nds.tlsattacker.tls.config.ClientCommandConfig;
import de.rub.nds.tlsattacker.tls.config.converters.FileConverter;
import de.rub.nds.tlsattacker.tls.config.validators.PercentageValidator;
import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.logging.Logger;

/**
 * A Config File which controls the EvolutionaryFuzzer.
 * 
 * @author Robert Merget - robert.merget@rub.de
 * @author Juraj Somorovsky <juraj.somorovsky@rub.de>
 */
public class SimpleMutatorConfig extends ClientCommandConfig {

    private Integer modifyVariablePercentage = 90;
    private Integer addRecordPercentage = 50;
    private Integer addMessagePercentage = 50;
    private Integer removeMessagePercentage = 1;
    private Integer changeServerCert = 1;
    private Integer changeClientCert = 1;
    private Integer duplicateMessagePercentage = 1;
    private Integer multipleModifications = 1;

    public SimpleMutatorConfig() {
    }

    public Integer getMultipleModifications() {
	return multipleModifications;
    }

    public void setMultipleModifications(Integer multipleModifications) {
	this.multipleModifications = multipleModifications;
    }

    public Integer getChangeServerCert() {
	return changeServerCert;
    }

    public void setChangeServerCert(Integer changeServerCert) {
	this.changeServerCert = changeServerCert;
    }

    public Integer getChangeClientCert() {
	return changeClientCert;
    }

    public void setChangeClientCert(Integer changeClientCert) {
	this.changeClientCert = changeClientCert;
    }

    public Integer getDuplicateMessagePercentage() {
	return duplicateMessagePercentage;
    }

    public void setDuplicateMessagePercentage(Integer duplicateMessagePercentage) {
	this.duplicateMessagePercentage = duplicateMessagePercentage;
    }

    public Integer getRemoveMessagePercentage() {
	return removeMessagePercentage;
    }

    public void setRemoveMessagePercentage(Integer removeMessagePercentage) {
	this.removeMessagePercentage = removeMessagePercentage;
	if (removeMessagePercentage > 100) {
	    throw new IllegalArgumentException("RemoveMessagePercentage cannot be >100:" + verifyWorkflowCorrectness);
	}
    }

    /**
     * Returns an Integer representing the chance that a Variable Modification
     * occurs in a Workflow Trace, 0 representing 0% and 100 representing 100%
     * 
     * @return
     */
    public Integer getModifyVariablePercentage() {
	return modifyVariablePercentage;
    }

    /**
     * Sets an Integer representing the chance that a Variable Modification
     * occurs in a Workflow Trace, 0 representing 0% and 100 representing 100%
     * 
     * @param modifyVariablePercentage
     */
    public void setModifyVariablePercentage(Integer modifyVariablePercentage) {
	this.modifyVariablePercentage = modifyVariablePercentage;
	if (modifyVariablePercentage > 100) {
	    throw new IllegalArgumentException("ModifyVariablePercentage cannot be >100:" + verifyWorkflowCorrectness);
	}
    }

    /**
     * Gets an Integer representing the Chance that a record is added to a
     * Message, 0 representing 0% and 100 representing 100%
     * 
     * @return Integer representing the Chance that a record is added to a
     *         Message
     */
    public Integer getAddRecordPercentage() {
	return addRecordPercentage;

    }

    /**
     * Sets an Integer representing the Chance that a record is added to a
     * Message, 0 representing 0% and 100 representing 100%
     * 
     * @param addRecordPercentage
     */
    public void setAddRecordPercentage(Integer addRecordPercentage) {
	this.addRecordPercentage = addRecordPercentage;
	if (addRecordPercentage > 100) {
	    throw new IllegalArgumentException("AddRecordPercentage cannot be >100:" + verifyWorkflowCorrectness);
	}
    }

    /**
     * Gets an Integer representing the Chance that a Message is added to
     * WorkflowTrace, 0 representing 0% and 100 representing 100%
     * 
     * @return Integer representing the Chance that a Message is added to
     *         WorkflowTrace
     */
    public Integer getAddMessagePercentage() {
	return addMessagePercentage;
    }

    /**
     * Sets an Integer representing the Chance that a Message is added to
     * WorkflowTrace, 0 representing 0% and 100 representing 100%
     * 
     * @param addMessagePercentage
     */
    public void setAddMessagePercentage(Integer addMessagePercentage) {
	this.addMessagePercentage = addMessagePercentage;
	if (addMessagePercentage > 100) {
	    throw new IllegalArgumentException("AddMessagePercentage cannot be >100:" + verifyWorkflowCorrectness);
	}
    }
}
