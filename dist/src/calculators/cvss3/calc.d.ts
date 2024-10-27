/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v3.0/specification-document
 */
import { CVSS3Info } from '../../types/fields/cvss3.js';
export declare class CVSS3Calculator {
    baseScore: number;
    impactSubScore: number;
    exploitabilitySubScore: number;
    temporalScore: number;
    environmentalScore: number;
    cvss3Info: CVSS3Info;
    /******************************************************************************/
    /**                             Public Methods                                */
    /******************************************************************************/
    /**
     * Compute the CVSS 3 base score from the parsed CVSS 2 Vector
     * @param cvss3Info the parsed CVSS 3 Vector
     * @returns the base score
     */
    computeBaseScore(cvss3Info: CVSS3Info): number;
    /**
     * Compute the CVSS 3 temporal score from the parsed CVSS 3 Vector
     * @param cvss3Info the parsed CVSS 3 Vector
     * @returns the temporal score
     */
    computeTemporalScore(cvss3Info: CVSS3Info): number;
    /**
     * Compute the CVSS 3 environmental score from the parsed CVSS 3 Vector
     * @param cvss3Info the parsed CVSS 3 Vector
     * @returns the temporal score
     */
    computeEnvironmentalScore(cvss3Info: CVSS3Info): number;
    /**
     * Returns the base score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the base score
     */
    getBaseScore(roundUpVal: boolean): number;
    /**
     * Returns the temporal score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the temporal score
     */
    getTemporalScore(roundUpVal: boolean): number;
    /**
     * Returns the environmental score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the environmental score
     */
    getEnvironmentalScore(roundUpVal: boolean): number;
    /**
     * Returns the impact subscore
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the impact subscore
     */
    getImpactSubScore(roundUpVal: boolean): number;
    /**
     * Returns the exploitability subscore
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the exploitability subscore
     */
    getExploitabilitySubScore(roundUpVal: boolean): number;
    /******************************************************************************/
    /**                          Base Score calculation                           */
    /******************************************************************************/
    private computeExploitabilitySubScore;
    private computeImpactSubScore;
    private computeBaseImpactSubScore;
    private computeConfidentialityImpact;
    private computeIntegrityImpact;
    private computeAvailabilityImpact;
    private computeAttackVector;
    private computeAttackComplexity;
    private computePrivilegesRequired;
    private computeUserInteraction;
    /******************************************************************************/
    /**                        Temporal Score calculation                         */
    /******************************************************************************/
    private computeExploitCodeMaturity;
    private computeRemediationLevel;
    private computeReportConfidence;
    /******************************************************************************/
    /**                      Environmental Score calculation                      */
    /******************************************************************************/
    private computeModifiedExploitabilitySubScore;
    private computeModifiedImpactSubScore;
    private computeIscModified;
    private computeConfidentialityRequirement;
    private computeAvailabilityRequirement;
    private computeIntegrityRequirement;
}
