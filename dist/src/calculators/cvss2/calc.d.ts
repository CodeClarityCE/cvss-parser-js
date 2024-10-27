/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v2/guide
 */
import { CVSS2Info } from '../../types/fields/cvss2.js';
export declare class CVSS2Calculator {
    baseScore: number;
    impactSubScore: number;
    exploitabilitySubScore: number;
    temporalScore: number;
    environmentalScore: number;
    cvss2Info: CVSS2Info;
    /******************************************************************************/
    /**                             Public Methods                                */
    /******************************************************************************/
    /**
     * Compute the CVSS 2 base score from the parsed CVSS 2 Vector
     * @param cvss2Info the parsed CVSS 2 Vector
     * @returns the base score
     */
    computeBaseScore(cvss2Info: CVSS2Info): number;
    /**
     * Compute the CVSS 2 temporal score from the parsed CVSS 2 Vector
     * @param cvss2Info the parsed CVSS 2 Vector
     * @returns the temporal score
     */
    computeTemporalScore(cvss2Info: CVSS2Info): number;
    /**
     * Compute the CVSS 2 environmental score from the parsed CVSS 2 Vector
     * @param cvss2Info the parsed CVSS 2 Vector
     * @returns the temporal score
     */
    computeEnvironmentalScore(cvss2Info: CVSS2Info): number;
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
    /**
     * Compute the CVSS 2 Impact Subscore
     * @returns the impact subscore
     */
    private computeImpactSubscore;
    /**
     * Compute the CVSS 2 Exploitability Subscore
     * @returns the exploitability subscore
     */
    private computeExploitabilitySubscore;
    /**
     * Transform discrete access vector to a continous score
     * @returns the continous score
     */
    private computeAccessVector;
    /**
     * Transform discrete access complexity to a continous score
     * @returns the continous score
     */
    private computeAccessComplexity;
    /**
     * Transform discrete authentication field to a continous score
     * @returns the continous score
     */
    private computeAuthentication;
    /**
     * Transform confidentiality impact field to a continous score
     * @returns the continous score
     */
    private computeConfImpact;
    /**
     * Transform availability impact field to a continous score
     * @returns the continous score
     */
    private computeAvailImpact;
    /**
     * Transform integrity impact field to a continous score
     * @returns the continous score
     */
    private computeIntegImpact;
    /******************************************************************************/
    /**                        Temporal Score calculation                         */
    /******************************************************************************/
    private computeExploitability;
    private computeRemediationLevel;
    private computeReportConfidence;
    /******************************************************************************/
    /**                      Environmental Score calculation                      */
    /******************************************************************************/
    private computeAdjustedTemportalScore;
    private computeAdjustedBaseSubScore;
    private computeAdjustedImpactScore;
    private computeCollateralDamangePotential;
    private computeTargetDistribution;
    private computeConfidentialityRequirement;
    private computeAvailabilityRequirement;
    private computeIntegrityRequirement;
}
