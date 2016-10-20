package tlsattacker.fuzzer.config.mutator;

import java.io.Serializable;
import java.util.logging.Logger;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A Config File which controls the SimpleMutator.
 * 
 * @author Robert Merget - robert.merget@rub.de
 */
@XmlRootElement
public class SimpleMutatorConfig implements Serializable {

    /**
     *
     */
    private Integer modifyVariablePercentage = 50;

    /**
     *
     */
    private Integer addRecordPercentage = 50;

    /**
     *
     */
    private Integer addMessagePercentage = 20;

    /**
     *
     */
    private Integer removeMessagePercentage = 1;

    /**
     *
     */
    private Integer changeServerCertPercentage = -1;

    /**
     *
     */
    private Integer changeClientCertPercentage = -1;

    /**
     *
     */
    private Integer duplicateMessagePercentage = 1;

    /**
     *
     */
    private Integer multipleModifications = 1;

    /**
     *
     */
    private Integer addFlightPercentage = 50;

    /**
     *
     */
    private Integer addToggleEncrytionPercentage = 2;

    /**
     *
     */
    private Integer addContextActionPercentage = 4;

    /**
     *
     */
    private Integer addExtensionMessagePercentage = 20;

    /**
     *
     */
    public SimpleMutatorConfig() {
    }

    /**
     *
     * @return
     */
    public Integer getAddExtensionPercentage() {
        return addExtensionMessagePercentage;
    }

    /**
     *
     * @param addExtensionMessagePercentage
     */
    public void setAddExtensionMessagePercentage(Integer addExtensionMessagePercentage) {
        this.addExtensionMessagePercentage = addExtensionMessagePercentage;
    }

    /**
     *
     * @return
     */
    public Integer getAddContextActionPercentage() {
        return addContextActionPercentage;
    }

    /**
     *
     * @param addContextActionPercentage
     */
    public void setAddContextActionPercentage(Integer addContextActionPercentage) {
        this.addContextActionPercentage = addContextActionPercentage;
    }

    /**
     *
     * @return
     */
    public Integer getAddToggleEncrytionPercentage() {
	return addToggleEncrytionPercentage;
    }

    /**
     *
     * @param addToggleEncrytionPercentage
     */
    public void setAddToggleEncrytionPercentage(Integer addToggleEncrytionPercentage) {
	this.addToggleEncrytionPercentage = addToggleEncrytionPercentage;
    }

    /**
     *
     * @return
     */
    public Integer getAddFlightPercentage() {
	return addFlightPercentage;
    }

    /**
     *
     * @param addFlightPercentage
     */
    public void setAddFlightPercentage(Integer addFlightPercentage) {
	this.addFlightPercentage = addFlightPercentage;
    }

    /**
     *
     * @return
     */
    public Integer getMultipleModifications() {
	return multipleModifications;
    }

    /**
     *
     * @param multipleModifications
     */
    public void setMultipleModifications(Integer multipleModifications) {
	this.multipleModifications = multipleModifications;
    }

    /**
     *
     * @return
     */
    public Integer getChangeServerCert() {
	return changeServerCertPercentage;
    }

    /**
     *
     * @param changeServerCert
     */
    public void setChangeServerCert(Integer changeServerCert) {
	this.changeServerCertPercentage = changeServerCert;
    }

    /**
     *
     * @return
     */
    public Integer getChangeClientCertPercentage() {
	return changeClientCertPercentage;
    }

    /**
     *
     * @param changeClientCertPercentage
     */
    public void setChangeClientCertPercentage(Integer changeClientCertPercentage) {
	this.changeClientCertPercentage = changeClientCertPercentage;
    }

    /**
     *
     * @return
     */
    public Integer getDuplicateMessagePercentage() {
	return duplicateMessagePercentage;
    }

    /**
     *
     * @param duplicateMessagePercentage
     */
    public void setDuplicateMessagePercentage(Integer duplicateMessagePercentage) {
	this.duplicateMessagePercentage = duplicateMessagePercentage;
    }

    /**
     *
     * @return
     */
    public Integer getRemoveMessagePercentage() {
	return removeMessagePercentage;
    }

    /**
     *
     * @param removeMessagePercentage
     */
    public void setRemoveMessagePercentage(Integer removeMessagePercentage) {
	this.removeMessagePercentage = removeMessagePercentage;
	if (removeMessagePercentage > 100) {
	    throw new IllegalArgumentException("RemoveMessagePercentage cannot be >100:" + removeMessagePercentage);
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
	    throw new IllegalArgumentException("ModifyVariablePercentage cannot be >100:" + modifyVariablePercentage);
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
	    throw new IllegalArgumentException("AddRecordPercentage cannot be >100:" + addRecordPercentage);
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
	    throw new IllegalArgumentException("AddMessagePercentage cannot be >100:" + addMessagePercentage);
	}
    }
    private static final Logger LOG = Logger.getLogger(SimpleMutatorConfig.class.getName());
}
