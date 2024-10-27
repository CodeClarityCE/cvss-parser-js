'use strict';

/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v2/guide
 */
/******************************************************************************/
/**                                 Base Metrics                              */
/******************************************************************************/
/**
 * Access Vector (AV)
 */
var AccessVector;
(function (AccessVector) {
    AccessVector["NOT_DEFINED"] = "NOT_DEFINED";
    AccessVector["LOCAL"] = "LOCAL";
    AccessVector["ADJACENT_NETWORK"] = "ADJACENT_NETWORK";
    AccessVector["NETWORK"] = "NETWORK";
})(AccessVector || (AccessVector = {}));
/**
 * Access Complexity (AC)
 */
var AccessComplexity;
(function (AccessComplexity) {
    AccessComplexity["NOT_DEFINED"] = "NOT_DEFINED";
    AccessComplexity["LOW"] = "LOW";
    AccessComplexity["MEDIUM"] = "MEDIUM";
    AccessComplexity["HIGH"] = "HIGH";
})(AccessComplexity || (AccessComplexity = {}));
/**
 * Authentication (Au)
 */
var Authentication;
(function (Authentication) {
    Authentication["NOT_DEFINED"] = "NOT_DEFINED";
    Authentication["MULTIPLE"] = "MULTIPLE";
    Authentication["SINGLE"] = "SINGLE";
    Authentication["NONE"] = "NONE";
})(Authentication || (Authentication = {}));
/**
 * Impact (C, A, I)
 */
var Impact$2;
(function (Impact) {
    Impact["NOT_DEFINED"] = "NOT_DEFINED";
    Impact["NONE"] = "NONE";
    Impact["PARTIAL"] = "PARTIAL";
    Impact["COMPLETE"] = "COMPLETE";
})(Impact$2 || (Impact$2 = {}));
/******************************************************************************/
/**                               Temporal Metrics                            */
/******************************************************************************/
/**
 * Exploitability (E)
 */
var Exploitability;
(function (Exploitability) {
    Exploitability["NOT_DEFINED"] = "NOT_DEFINED";
    Exploitability["UNPROVEN"] = "UNPROVEN";
    Exploitability["PROOF_OF_CONCEPT"] = "PROOF_OF_CONCEPT";
    Exploitability["FUNCTIONAL"] = "FUNCTIONAL";
    Exploitability["HIGH"] = "HIGH";
})(Exploitability || (Exploitability = {}));
/**
 * Remediation Level (RL)
 */
var RemediationLevel$2;
(function (RemediationLevel) {
    RemediationLevel["NOT_DEFINED"] = "NOT_DEFINED";
    RemediationLevel["OFFICIAL_FIX"] = "OFFICIAL_FIX";
    RemediationLevel["TEMPORARY_FIX"] = "TEMPORARY_FIX";
    RemediationLevel["WORKAROUND"] = "WORKAROUND";
    RemediationLevel["UNAVAILABLE"] = "UNAVAILABLE";
})(RemediationLevel$2 || (RemediationLevel$2 = {}));
/**
 * Report Confidence (RC)
 */
var ReportConfidence$2;
(function (ReportConfidence) {
    ReportConfidence["NOT_DEFINED"] = "NOT_DEFINED";
    ReportConfidence["UNCONFIRMED"] = "UNCONFIRMED";
    ReportConfidence["UNCORROBORATED"] = "UNCORROBORATED";
    ReportConfidence["CONFIRMED"] = "CONFIRMED";
})(ReportConfidence$2 || (ReportConfidence$2 = {}));
/******************************************************************************/
/**                            Environmental Metrics                          */
/******************************************************************************/
/**
 * Collateral Damage Potential (CDP)
 */
var CollateralDamagePotential;
(function (CollateralDamagePotential) {
    CollateralDamagePotential["NOT_DEFINED"] = "NOT_DEFINED";
    CollateralDamagePotential["NONE"] = "NONE";
    CollateralDamagePotential["LOW"] = "LOW";
    CollateralDamagePotential["LOW_MEDIUM"] = "LOW_MEDIUM";
    CollateralDamagePotential["MEDIUM_HIGH"] = "MEDIUM_HIGH";
    CollateralDamagePotential["HIGH"] = "HIGH";
})(CollateralDamagePotential || (CollateralDamagePotential = {}));
/**
 * Target Distribution (TD)
 */
var TargetDistribution;
(function (TargetDistribution) {
    TargetDistribution["NOT_DEFINED"] = "NOT_DEFINED";
    TargetDistribution["NONE"] = "NONE";
    TargetDistribution["LOW"] = "LOW";
    TargetDistribution["MEDIUM"] = "MEDIUM";
    TargetDistribution["HIGH"] = "HIGH";
})(TargetDistribution || (TargetDistribution = {}));
/**
 * Security Requirements (CR, IR, AR)
 */
var SecurityRequirements$2;
(function (SecurityRequirements) {
    SecurityRequirements["NOT_DEFINED"] = "NOT_DEFINED";
    SecurityRequirements["LOW"] = "LOW";
    SecurityRequirements["MEDIUM"] = "MEDIUM";
    SecurityRequirements["HIGH"] = "HIGH";
})(SecurityRequirements$2 || (SecurityRequirements$2 = {}));

/**
 * Rounds the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
 * Spec: https://www.first.org/cvss/v3.1/specification-document#Appendix-A---Floating-Point-Rounding
 *
 * @param value the value to round
 * @returns the rounded value
 */
function roundUp(value) {
    const rounded = Math.round(value * 100000);
    if (rounded % 10000 == 0) {
        return rounded / 100000.0;
    }
    else {
        return (Math.floor(rounded / 10000) + 1) / 10.0;
    }
}

/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v2/guide
 */
class CVSS2Calculator {
    constructor() {
        this.baseScore = 0;
        this.impactSubScore = 0;
        this.exploitabilitySubScore = 0;
        this.temporalScore = 0;
        this.environmentalScore = 0;
        this.cvss2Info = {
            AccessVector: AccessVector.NOT_DEFINED,
            AccessComplexity: AccessComplexity.NOT_DEFINED,
            Authentication: Authentication.NOT_DEFINED,
            ConfidentialityImpact: Impact$2.NOT_DEFINED,
            IntegrityImpact: Impact$2.NOT_DEFINED,
            AvailabilityImpact: Impact$2.NOT_DEFINED,
            Exploitability: Exploitability.NOT_DEFINED,
            RemediationLevel: RemediationLevel$2.NOT_DEFINED,
            ReportConfidence: ReportConfidence$2.NOT_DEFINED,
            CollateralDamagePotential: CollateralDamagePotential.NOT_DEFINED,
            TargetDistribution: TargetDistribution.NOT_DEFINED,
            ConfidentialityRequirement: SecurityRequirements$2.NOT_DEFINED,
            IntegrityRequirement: SecurityRequirements$2.NOT_DEFINED,
            AvailabilityRequirement: SecurityRequirements$2.NOT_DEFINED
        };
    }
    /******************************************************************************/
    /**                             Public Methods                                */
    /******************************************************************************/
    /**
     * Compute the CVSS 2 base score from the parsed CVSS 2 Vector
     * @param cvss2Info the parsed CVSS 2 Vector
     * @returns the base score
     */
    computeBaseScore(cvss2Info) {
        this.cvss2Info = cvss2Info;
        const impact = this.computeImpactSubscore();
        const exploitability = this.computeExploitabilitySubscore();
        const fImpact = impact == 0 ? 0 : 1.176;
        const baseScore = (0.6 * impact + 0.4 * exploitability - 1.5) * fImpact;
        this.baseScore = baseScore;
        return baseScore;
    }
    /**
     * Compute the CVSS 2 temporal score from the parsed CVSS 2 Vector
     * @param cvss2Info the parsed CVSS 2 Vector
     * @returns the temporal score
     */
    computeTemporalScore(cvss2Info) {
        this.cvss2Info = cvss2Info;
        if (this.baseScore == undefined) {
            this.computeBaseScore(cvss2Info);
        }
        const exploitability = this.computeExploitability();
        const remediationLevel = this.computeRemediationLevel();
        const reportConfidence = this.computeReportConfidence();
        const temporalScore = roundUp(this.baseScore * exploitability * remediationLevel * reportConfidence);
        this.temporalScore = temporalScore;
        return temporalScore;
    }
    /**
     * Compute the CVSS 2 environmental score from the parsed CVSS 2 Vector
     * @param cvss2Info the parsed CVSS 2 Vector
     * @returns the temporal score
     */
    computeEnvironmentalScore(cvss2Info) {
        this.cvss2Info = cvss2Info;
        const collateralDamagePotential = this.computeCollateralDamangePotential();
        const targetDistribution = this.computeTargetDistribution();
        const adjustedTemporal = this.computeAdjustedTemportalScore();
        const environmentalScore = roundUp((adjustedTemporal + (10 - adjustedTemporal) * collateralDamagePotential) *
            targetDistribution);
        this.environmentalScore = environmentalScore;
        return environmentalScore;
    }
    /**
     * Returns the base score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the base score
     */
    getBaseScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.baseScore);
        return this.baseScore;
    }
    /**
     * Returns the temporal score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the temporal score
     */
    getTemporalScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.temporalScore);
        return this.temporalScore;
    }
    /**
     * Returns the environmental score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the environmental score
     */
    getEnvironmentalScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.environmentalScore);
        return this.environmentalScore;
    }
    /**
     * Returns the impact subscore
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the impact subscore
     */
    getImpactSubScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.impactSubScore);
        return this.impactSubScore;
    }
    /**
     * Returns the exploitability subscore
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the exploitability subscore
     */
    getExploitabilitySubScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.exploitabilitySubScore);
        return this.exploitabilitySubScore;
    }
    /******************************************************************************/
    /**                          Base Score calculation                           */
    /******************************************************************************/
    /**
     * Compute the CVSS 2 Impact Subscore
     * @returns the impact subscore
     */
    computeImpactSubscore() {
        const confImpact = this.computeConfImpact();
        const integImpact = this.computeAvailImpact();
        const availImpact = this.computeIntegImpact();
        const impactScore = 10.41 * (1 - (1 - confImpact) * (1 - integImpact) * (1 - availImpact));
        this.impactSubScore = impactScore;
        return impactScore;
    }
    /**
     * Compute the CVSS 2 Exploitability Subscore
     * @returns the exploitability subscore
     */
    computeExploitabilitySubscore() {
        const accessVector = this.computeAccessVector();
        const accessComplexity = this.computeAccessComplexity();
        const authentication = this.computeAuthentication();
        const exploitabilityScore = 20 * accessVector * accessComplexity * authentication;
        this.exploitabilitySubScore = exploitabilityScore;
        return exploitabilityScore;
    }
    /**
     * Transform discrete access vector to a continous score
     * @returns the continous score
     */
    computeAccessVector() {
        switch (this.cvss2Info.AccessVector) {
            case AccessVector.LOCAL:
                return 0.395;
            case AccessVector.ADJACENT_NETWORK:
                return 0.646;
            case AccessVector.NETWORK:
                return 1.0;
            default:
                return 0.0;
        }
    }
    /**
     * Transform discrete access complexity to a continous score
     * @returns the continous score
     */
    computeAccessComplexity() {
        switch (this.cvss2Info.AccessComplexity) {
            case AccessComplexity.HIGH:
                return 0.35;
            case AccessComplexity.MEDIUM:
                return 0.61;
            case AccessComplexity.LOW:
                return 0.71;
            default:
                return 0.0;
        }
    }
    /**
     * Transform discrete authentication field to a continous score
     * @returns the continous score
     */
    computeAuthentication() {
        switch (this.cvss2Info.Authentication) {
            case Authentication.MULTIPLE:
                return 0.45;
            case Authentication.SINGLE:
                return 0.56;
            case Authentication.NONE:
                return 0.704;
            default:
                return 0.0;
        }
    }
    /**
     * Transform confidentiality impact field to a continous score
     * @returns the continous score
     */
    computeConfImpact() {
        switch (this.cvss2Info.ConfidentialityImpact) {
            case Impact$2.NONE:
                return 0.0;
            case Impact$2.PARTIAL:
                return 0.275;
            case Impact$2.COMPLETE:
                return 0.66;
            default:
                return 0.0;
        }
    }
    /**
     * Transform availability impact field to a continous score
     * @returns the continous score
     */
    computeAvailImpact() {
        switch (this.cvss2Info.AvailabilityImpact) {
            case Impact$2.NONE:
                return 0.0;
            case Impact$2.PARTIAL:
                return 0.275;
            case Impact$2.COMPLETE:
                return 0.66;
            default:
                return 0.0;
        }
    }
    /**
     * Transform integrity impact field to a continous score
     * @returns the continous score
     */
    computeIntegImpact() {
        switch (this.cvss2Info.IntegrityImpact) {
            case Impact$2.NONE:
                return 0.0;
            case Impact$2.PARTIAL:
                return 0.275;
            case Impact$2.COMPLETE:
                return 0.66;
            default:
                return 0.0;
        }
    }
    /******************************************************************************/
    /**                        Temporal Score calculation                         */
    /******************************************************************************/
    computeExploitability() {
        switch (this.cvss2Info.Exploitability) {
            case Exploitability.UNPROVEN:
                return 0.85;
            case Exploitability.PROOF_OF_CONCEPT:
                return 0.9;
            case Exploitability.FUNCTIONAL:
                return 0.95;
            case Exploitability.HIGH:
                return 1.0;
            default:
                return 1.0;
        }
    }
    computeRemediationLevel() {
        switch (this.cvss2Info.RemediationLevel) {
            case RemediationLevel$2.OFFICIAL_FIX:
                return 0.87;
            case RemediationLevel$2.TEMPORARY_FIX:
                return 0.9;
            case RemediationLevel$2.WORKAROUND:
                return 0.95;
            case RemediationLevel$2.UNAVAILABLE:
                return 1.0;
            default:
                return 1.0;
        }
    }
    computeReportConfidence() {
        switch (this.cvss2Info.ReportConfidence) {
            case ReportConfidence$2.UNCONFIRMED:
                return 0.9;
            case ReportConfidence$2.UNCORROBORATED:
                return 0.95;
            case ReportConfidence$2.CONFIRMED:
                return 1.0;
            default:
                return 1.0;
        }
    }
    /******************************************************************************/
    /**                      Environmental Score calculation                      */
    /******************************************************************************/
    computeAdjustedTemportalScore() {
        const baseScore = this.computeAdjustedBaseSubScore();
        const exploitability = this.computeExploitability();
        const remediationLevel = this.computeRemediationLevel();
        const reportConfidence = this.computeReportConfidence();
        return baseScore * exploitability * remediationLevel * reportConfidence;
    }
    computeAdjustedBaseSubScore() {
        const impact = this.computeAdjustedImpactScore();
        const exploitability = this.computeExploitabilitySubscore();
        const fImpact = impact == 0 ? 0 : 1.176;
        let baseScore = (0.6 * impact + 0.4 * exploitability - 1.5) * fImpact;
        baseScore = Math.round(baseScore * 10) / 10; // round to one decimal place
        this.baseScore = baseScore;
        return baseScore;
    }
    computeAdjustedImpactScore() {
        const confidentialityImpact = this.computeConfImpact();
        const integrityImpact = this.computeIntegImpact();
        const availabilityImpact = this.computeAvailImpact();
        const confidenialityRequirement = this.computeConfidentialityRequirement();
        const integrityRequirement = this.computeIntegrityRequirement();
        const availabilityRequirement = this.computeAvailabilityRequirement();
        const adjustedImpactScore = Math.min(10, 10.41 *
            (1 -
                (1 - confidentialityImpact * confidenialityRequirement) *
                    (1 - integrityImpact * integrityRequirement) *
                    (1 - availabilityImpact * availabilityRequirement)));
        return adjustedImpactScore;
    }
    computeCollateralDamangePotential() {
        switch (this.cvss2Info.CollateralDamagePotential) {
            case CollateralDamagePotential.NONE:
                return 0;
            case CollateralDamagePotential.LOW:
                return 0.1;
            case CollateralDamagePotential.LOW_MEDIUM:
                return 0.3;
            case CollateralDamagePotential.MEDIUM_HIGH:
                return 0.4;
            case CollateralDamagePotential.HIGH:
                return 0.5;
            default:
                return 0;
        }
    }
    computeTargetDistribution() {
        switch (this.cvss2Info.TargetDistribution) {
            case TargetDistribution.NONE:
                return 0;
            case TargetDistribution.LOW:
                return 0.25;
            case TargetDistribution.MEDIUM:
                return 0.75;
            case TargetDistribution.HIGH:
                return 1.0;
            default:
                return 1.0;
        }
    }
    computeConfidentialityRequirement() {
        switch (this.cvss2Info.ConfidentialityRequirement) {
            case SecurityRequirements$2.LOW:
                return 0.5;
            case SecurityRequirements$2.MEDIUM:
                return 1.0;
            case SecurityRequirements$2.HIGH:
                return 1.51;
            default:
                return 1.0;
        }
    }
    computeAvailabilityRequirement() {
        switch (this.cvss2Info.AvailabilityRequirement) {
            case SecurityRequirements$2.LOW:
                return 0.5;
            case SecurityRequirements$2.MEDIUM:
                return 1.0;
            case SecurityRequirements$2.HIGH:
                return 1.51;
            default:
                return 1.0;
        }
    }
    computeIntegrityRequirement() {
        switch (this.cvss2Info.IntegrityRequirement) {
            case SecurityRequirements$2.LOW:
                return 0.5;
            case SecurityRequirements$2.MEDIUM:
                return 1.0;
            case SecurityRequirements$2.HIGH:
                return 1.51;
            default:
                return 1.0;
        }
    }
}

/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v3.0/specification-document
 */
/******************************************************************************/
/**                                 Base Metrics                              */
/******************************************************************************/
/**
 * Attack Vector (AV)
 */
var AttackVector$1;
(function (AttackVector) {
    AttackVector["NOT_DEFINED"] = "NOT_DEFINED";
    AttackVector["PHYSICAL"] = "PHYSICAL";
    AttackVector["LOCAL"] = "LOCAL";
    AttackVector["ADJACENT_NETWORK"] = "ADJACENT_NETWORK";
    AttackVector["NETWORK"] = "NETWORK";
})(AttackVector$1 || (AttackVector$1 = {}));
/**
 * Attack Complexity (AC)
 */
var AttackComplexity$1;
(function (AttackComplexity) {
    AttackComplexity["NOT_DEFINED"] = "NOT_DEFINED";
    AttackComplexity["LOW"] = "LOW";
    AttackComplexity["HIGH"] = "HIGH";
})(AttackComplexity$1 || (AttackComplexity$1 = {}));
/**
 * Privileges Required (PR)
 */
var PrivilegesRequired$1;
(function (PrivilegesRequired) {
    PrivilegesRequired["NOT_DEFINED"] = "NOT_DEFINED";
    PrivilegesRequired["HIGH"] = "HIGH";
    PrivilegesRequired["LOW"] = "LOW";
    PrivilegesRequired["NONE"] = "NONE";
})(PrivilegesRequired$1 || (PrivilegesRequired$1 = {}));
/**
 * User Interaction (UI)
 */
var UserInteraction$1;
(function (UserInteraction) {
    UserInteraction["NOT_DEFINED"] = "NOT_DEFINED";
    UserInteraction["REQUIRED"] = "REQUIRED";
    UserInteraction["NONE"] = "NONE";
})(UserInteraction$1 || (UserInteraction$1 = {}));
/**
 * Scope (S)
 */
var Scope$1;
(function (Scope) {
    Scope["NOT_DEFINED"] = "NOT_DEFINED";
    Scope["UNCHANGED"] = "UNCHANGED";
    Scope["CHANGED"] = "CHANGED";
})(Scope$1 || (Scope$1 = {}));
/**
 * Impact (C, A, I)
 */
var Impact$1;
(function (Impact) {
    Impact["NOT_DEFINED"] = "NOT_DEFINED";
    Impact["NONE"] = "NONE";
    Impact["LOW"] = "LOW";
    Impact["HIGH"] = "HIGH";
})(Impact$1 || (Impact$1 = {}));
/******************************************************************************/
/**                               Temporal Metrics                            */
/******************************************************************************/
/**
 * Exploit Code Maturity (E)
 */
var ExploitCodeMaturity$1;
(function (ExploitCodeMaturity) {
    ExploitCodeMaturity["NOT_DEFINED"] = "NOT_DEFINED";
    ExploitCodeMaturity["UNPROVEN"] = "UNPROVEN";
    ExploitCodeMaturity["FUNCTIONAL"] = "FUNCTIONAL";
    ExploitCodeMaturity["PROOF_OF_CONCEPT"] = "PROOF_OF_CONCEPT";
    ExploitCodeMaturity["HIGH"] = "HIGH";
})(ExploitCodeMaturity$1 || (ExploitCodeMaturity$1 = {}));
/**
 * Remediation Level (RL)
 */
var RemediationLevel$1;
(function (RemediationLevel) {
    RemediationLevel["NOT_DEFINED"] = "NOT_DEFINED";
    RemediationLevel["OFFICIAL_FIX"] = "OFFICIAL_FIX";
    RemediationLevel["TEMPORARY_FIX"] = "TEMPORARY_FIX";
    RemediationLevel["WORKAROUND"] = "WORKAROUND";
    RemediationLevel["UNAVAILABLE"] = "UNAVAILABLE";
})(RemediationLevel$1 || (RemediationLevel$1 = {}));
/**
 * Report Confidence (RC)
 */
var ReportConfidence$1;
(function (ReportConfidence) {
    ReportConfidence["NOT_DEFINED"] = "NOT_DEFINED";
    ReportConfidence["UNKNOWN"] = "UNKNOWN";
    ReportConfidence["REASONABLE"] = "REASONABLE";
    ReportConfidence["CONFIRMED"] = "CONFIRMED";
})(ReportConfidence$1 || (ReportConfidence$1 = {}));
/******************************************************************************/
/**                            Environmental Metrics                          */
/******************************************************************************/
/**
 * Security Requirements (CR, IR, AR)
 */
var SecurityRequirements$1;
(function (SecurityRequirements) {
    SecurityRequirements["NOT_DEFINED"] = "NOT_DEFINED";
    SecurityRequirements["LOW"] = "LOW";
    SecurityRequirements["MEDIUM"] = "MEDIUM";
    SecurityRequirements["HIGH"] = "HIGH";
})(SecurityRequirements$1 || (SecurityRequirements$1 = {}));

/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v3.0/specification-document
 */
class CVSS3Calculator {
    constructor() {
        this.baseScore = 0;
        this.impactSubScore = 0;
        this.exploitabilitySubScore = 0;
        this.temporalScore = 0;
        this.environmentalScore = 0;
        this.cvss3Info = {
            AttackVector: AttackVector$1.NOT_DEFINED,
            AttackComplexity: AttackComplexity$1.NOT_DEFINED,
            PrivilegesRequired: PrivilegesRequired$1.NOT_DEFINED,
            UserInteraction: UserInteraction$1.NOT_DEFINED,
            Scope: Scope$1.NOT_DEFINED,
            ConfidentialityImpact: Impact$1.NOT_DEFINED,
            IntegrityImpact: Impact$1.NOT_DEFINED,
            AvailabilityImpact: Impact$1.NOT_DEFINED,
            ExploitCodeMaturity: ExploitCodeMaturity$1.NOT_DEFINED,
            RemediationLevel: RemediationLevel$1.NOT_DEFINED,
            ReportConfidence: ReportConfidence$1.NOT_DEFINED,
            ConfidentialityRequirement: SecurityRequirements$1.NOT_DEFINED,
            IntegrityRequirement: SecurityRequirements$1.NOT_DEFINED,
            AvailabilityRequirement: SecurityRequirements$1.NOT_DEFINED
        };
    }
    /******************************************************************************/
    /**                             Public Methods                                */
    /******************************************************************************/
    /**
     * Compute the CVSS 3 base score from the parsed CVSS 2 Vector
     * @param cvss3Info the parsed CVSS 3 Vector
     * @returns the base score
     */
    computeBaseScore(cvss3Info) {
        this.cvss3Info = cvss3Info;
        const impactSubScore = this.computeImpactSubScore();
        const exploitabilitySubScore = this.computeExploitabilitySubScore();
        if (impactSubScore <= 0)
            return 0.0;
        let baseScore = 0.0;
        if (Scope$1.UNCHANGED) {
            baseScore = Math.min(impactSubScore + exploitabilitySubScore, 10);
        }
        else if (Scope$1.CHANGED) {
            baseScore = Math.min(1.08 * (impactSubScore + exploitabilitySubScore), 10);
        }
        this.baseScore = baseScore;
        return this.baseScore;
    }
    /**
     * Compute the CVSS 3 temporal score from the parsed CVSS 3 Vector
     * @param cvss3Info the parsed CVSS 3 Vector
     * @returns the temporal score
     */
    computeTemporalScore(cvss3Info) {
        this.cvss3Info = cvss3Info;
        if (this.baseScore == undefined) {
            this.computeBaseScore(cvss3Info);
        }
        const exploitCodeMaturity = this.computeExploitCodeMaturity();
        const remediationLevel = this.computeRemediationLevel();
        const reportConfidence = this.computeReportConfidence();
        const temporalScore = roundUp(this.baseScore * exploitCodeMaturity * remediationLevel * reportConfidence);
        this.temporalScore = temporalScore;
        return temporalScore;
    }
    /**
     * Compute the CVSS 3 environmental score from the parsed CVSS 3 Vector
     * @param cvss3Info the parsed CVSS 3 Vector
     * @returns the temporal score
     */
    computeEnvironmentalScore(cvss3Info) {
        this.cvss3Info = cvss3Info;
        const modifiedImpactSubScore = this.computeModifiedImpactSubScore();
        const modifiedExploitabilitySubScore = this.computeModifiedExploitabilitySubScore();
        const exploitCodeMaturity = this.computeExploitCodeMaturity();
        const remediationLevel = this.computeRemediationLevel();
        const reportConfidence = this.computeRemediationLevel();
        if (modifiedImpactSubScore <= 0)
            return 0.0;
        let environmentalScore = 0.0;
        if (this.cvss3Info.Scope == Scope$1.UNCHANGED) {
            environmentalScore = roundUp(roundUp(Math.min(modifiedImpactSubScore + modifiedExploitabilitySubScore, 10.0)) *
                exploitCodeMaturity *
                remediationLevel *
                reportConfidence);
        }
        else if (this.cvss3Info.Scope == Scope$1.CHANGED) {
            environmentalScore = roundUp(roundUp(Math.min(1.08 * (modifiedImpactSubScore + modifiedExploitabilitySubScore), 10.0)) *
                exploitCodeMaturity *
                remediationLevel *
                reportConfidence);
        }
        this.environmentalScore = environmentalScore;
        return environmentalScore;
    }
    /**
     * Returns the base score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the base score
     */
    getBaseScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.baseScore);
        return this.baseScore;
    }
    /**
     * Returns the temporal score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the temporal score
     */
    getTemporalScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.temporalScore);
        return this.temporalScore;
    }
    /**
     * Returns the environmental score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the environmental score
     */
    getEnvironmentalScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.environmentalScore);
        return this.environmentalScore;
    }
    /**
     * Returns the impact subscore
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the impact subscore
     */
    getImpactSubScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.impactSubScore);
        return this.impactSubScore;
    }
    /**
     * Returns the exploitability subscore
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the exploitability subscore
     */
    getExploitabilitySubScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.exploitabilitySubScore);
        return this.exploitabilitySubScore;
    }
    /******************************************************************************/
    /**                          Base Score calculation                           */
    /******************************************************************************/
    computeExploitabilitySubScore() {
        const attackVector = this.computeAttackVector();
        const attackComplexity = this.computeAttackComplexity();
        const privilegesRequired = this.computePrivilegesRequired();
        const userInteraction = this.computeUserInteraction();
        const exploitabilitySubScore = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;
        this.exploitabilitySubScore = exploitabilitySubScore;
        return exploitabilitySubScore;
    }
    computeImpactSubScore() {
        const baseImpactScore = this.computeBaseImpactSubScore();
        if (this.cvss3Info.Scope == Scope$1.UNCHANGED) {
            const impactSubScore = 6.42 * baseImpactScore;
            this.impactSubScore = impactSubScore;
            return impactSubScore;
        }
        const impactSubScore = 7.52 * (baseImpactScore - 0.029) - 3.25 * Math.pow(baseImpactScore - 0.02, 15);
        this.impactSubScore = impactSubScore;
        return impactSubScore;
    }
    computeBaseImpactSubScore() {
        const confidentialityImpact = this.computeConfidentialityImpact();
        const integrityImpact = this.computeIntegrityImpact();
        const availabilityImpact = this.computeAvailabilityImpact();
        // Compute and return the base impact subscore (called ISC_Base) in the specification.
        return 1 - (1 - confidentialityImpact) * (1 - integrityImpact) * (1 - availabilityImpact);
    }
    computeConfidentialityImpact() {
        switch (this.cvss3Info.ConfidentialityImpact) {
            case Impact$1.NONE:
                return 0.0;
            case Impact$1.LOW:
                return 0.22;
            case Impact$1.HIGH:
                return 0.56;
            default:
                return 0.0;
        }
    }
    computeIntegrityImpact() {
        switch (this.cvss3Info.IntegrityImpact) {
            case Impact$1.NONE:
                return 0.0;
            case Impact$1.LOW:
                return 0.22;
            case Impact$1.HIGH:
                return 0.56;
            default:
                return 0.0;
        }
    }
    computeAvailabilityImpact() {
        switch (this.cvss3Info.AvailabilityImpact) {
            case Impact$1.NONE:
                return 0.0;
            case Impact$1.LOW:
                return 0.22;
            case Impact$1.HIGH:
                return 0.56;
            default:
                return 0.0;
        }
    }
    computeAttackVector() {
        switch (this.cvss3Info.AttackVector) {
            case AttackVector$1.NETWORK:
                return 0.85;
            case AttackVector$1.ADJACENT_NETWORK:
                return 0.62;
            case AttackVector$1.LOCAL:
                return 0.55;
            case AttackVector$1.PHYSICAL:
                return 0.2;
            default:
                return 0.0;
        }
    }
    computeAttackComplexity() {
        switch (this.cvss3Info.AttackComplexity) {
            case AttackComplexity$1.LOW:
                return 0.77;
            case AttackComplexity$1.HIGH:
                return 0.44;
            default:
                return 0.0;
        }
    }
    computePrivilegesRequired() {
        switch (this.cvss3Info.PrivilegesRequired) {
            case PrivilegesRequired$1.NONE:
                return 0.85;
            case PrivilegesRequired$1.LOW:
                return this.cvss3Info.Scope == Scope$1.CHANGED ? 0.68 : 0.62;
            case PrivilegesRequired$1.HIGH:
                return this.cvss3Info.Scope == Scope$1.CHANGED ? 0.5 : 0.27;
            default:
                return 0.0;
        }
    }
    computeUserInteraction() {
        switch (this.cvss3Info.UserInteraction) {
            case UserInteraction$1.NONE:
                return 0.85;
            case UserInteraction$1.REQUIRED:
                return 0.62;
            default:
                return 0.0;
        }
    }
    /******************************************************************************/
    /**                        Temporal Score calculation                         */
    /******************************************************************************/
    computeExploitCodeMaturity() {
        switch (this.cvss3Info.ExploitCodeMaturity) {
            case ExploitCodeMaturity$1.NOT_DEFINED:
                return 1.0;
            case ExploitCodeMaturity$1.HIGH:
                return 1.0;
            case ExploitCodeMaturity$1.FUNCTIONAL:
                return 0.97;
            case ExploitCodeMaturity$1.PROOF_OF_CONCEPT:
                return 0.94;
            case ExploitCodeMaturity$1.UNPROVEN:
                return 0.91;
            default:
                return 1.0;
        }
    }
    computeRemediationLevel() {
        switch (this.cvss3Info.RemediationLevel) {
            case RemediationLevel$1.NOT_DEFINED:
                return 1.0;
            case RemediationLevel$1.UNAVAILABLE:
                return 1.0;
            case RemediationLevel$1.WORKAROUND:
                return 0.97;
            case RemediationLevel$1.TEMPORARY_FIX:
                return 0.96;
            case RemediationLevel$1.OFFICIAL_FIX:
                return 0.95;
            default:
                return 1.0;
        }
    }
    computeReportConfidence() {
        switch (this.cvss3Info.ReportConfidence) {
            case ReportConfidence$1.NOT_DEFINED:
                return 1.0;
            case ReportConfidence$1.CONFIRMED:
                return 1.0;
            case ReportConfidence$1.REASONABLE:
                return 0.96;
            case ReportConfidence$1.UNKNOWN:
                return 0.92;
            default:
                return 1.0;
        }
    }
    /******************************************************************************/
    /**                      Environmental Score calculation                      */
    /******************************************************************************/
    computeModifiedExploitabilitySubScore() {
        const attackVector = this.computeAttackVector();
        const attackComplexity = this.computeAttackComplexity();
        const privilegesRequired = this.computePrivilegesRequired();
        const userInteraction = this.computeUserInteraction();
        const exploitabilitySubScore = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;
        return exploitabilitySubScore;
    }
    computeModifiedImpactSubScore() {
        const iscModified = this.computeIscModified();
        if (this.cvss3Info.Scope === Scope$1.UNCHANGED) {
            return 6.42 * iscModified;
        }
        else if (this.cvss3Info.Scope === Scope$1.CHANGED) {
            return 7.52 * (iscModified - 0.029) - 3.25 * Math.pow(iscModified - 0.02, 15);
        }
        else {
            return 0.0;
        }
    }
    computeIscModified() {
        const modifiedConfidentialityImpact = this.computeConfidentialityImpact();
        const modifiedIntegrityImpact = this.computeIntegrityImpact();
        const modifiedAvailabilityImpact = this.computeAvailabilityImpact();
        const confidenialityRequirement = this.computeConfidentialityRequirement();
        const integrityRequirement = this.computeIntegrityRequirement();
        const availabilityRequirement = this.computeAvailabilityRequirement();
        const isc_modified = (1 - modifiedConfidentialityImpact * confidenialityRequirement) *
            (1 - modifiedIntegrityImpact * integrityRequirement) *
            (1 - modifiedAvailabilityImpact * availabilityRequirement);
        return Math.min(1 - isc_modified, 0.915);
    }
    computeConfidentialityRequirement() {
        switch (this.cvss3Info.ConfidentialityRequirement) {
            case SecurityRequirements$1.NOT_DEFINED:
                return 1.0;
            case SecurityRequirements$1.HIGH:
                return 1.5;
            case SecurityRequirements$1.MEDIUM:
                return 1.0;
            case SecurityRequirements$1.LOW:
                return 0.5;
            default:
                return 1.0;
        }
    }
    computeAvailabilityRequirement() {
        switch (this.cvss3Info.AvailabilityRequirement) {
            case SecurityRequirements$1.NOT_DEFINED:
                return 1.0;
            case SecurityRequirements$1.HIGH:
                return 1.5;
            case SecurityRequirements$1.MEDIUM:
                return 1.0;
            case SecurityRequirements$1.LOW:
                return 0.5;
            default:
                return 1.0;
        }
    }
    computeIntegrityRequirement() {
        switch (this.cvss3Info.IntegrityRequirement) {
            case SecurityRequirements$1.NOT_DEFINED:
                return 1.0;
            case SecurityRequirements$1.HIGH:
                return 1.5;
            case SecurityRequirements$1.MEDIUM:
                return 1.0;
            case SecurityRequirements$1.LOW:
                return 0.5;
            default:
                return 1.0;
        }
    }
}

/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v3.1/specification-document
 */
/******************************************************************************/
/**                                 Base Metrics                              */
/******************************************************************************/
/**
 * Attack Vector (AV)
 */
var AttackVector;
(function (AttackVector) {
    AttackVector["NOT_DEFINED"] = "NOT_DEFINED";
    AttackVector["PHYSICAL"] = "PHYSICAL";
    AttackVector["LOCAL"] = "LOCAL";
    AttackVector["ADJACENT_NETWORK"] = "ADJACENT_NETWORK";
    AttackVector["NETWORK"] = "NETWORK";
})(AttackVector || (AttackVector = {}));
/**
 * Attack Complexity (AC)
 */
var AttackComplexity;
(function (AttackComplexity) {
    AttackComplexity["NOT_DEFINED"] = "NOT_DEFINED";
    AttackComplexity["LOW"] = "LOW";
    AttackComplexity["HIGH"] = "HIGH";
})(AttackComplexity || (AttackComplexity = {}));
/**
 * Privileges Required (PR)
 */
var PrivilegesRequired;
(function (PrivilegesRequired) {
    PrivilegesRequired["NOT_DEFINED"] = "NOT_DEFINED";
    PrivilegesRequired["HIGH"] = "HIGH";
    PrivilegesRequired["LOW"] = "LOW";
    PrivilegesRequired["NONE"] = "NONE";
})(PrivilegesRequired || (PrivilegesRequired = {}));
/**
 * User Interaction (UI)
 */
var UserInteraction;
(function (UserInteraction) {
    UserInteraction["NOT_DEFINED"] = "NOT_DEFINED";
    UserInteraction["REQUIRED"] = "REQUIRED";
    UserInteraction["NONE"] = "NONE";
})(UserInteraction || (UserInteraction = {}));
/**
 * Scope (S)
 */
var Scope;
(function (Scope) {
    Scope["NOT_DEFINED"] = "NOT_DEFINED";
    Scope["UNCHANGED"] = "UNCHANGED";
    Scope["CHANGED"] = "CHANGED";
})(Scope || (Scope = {}));
/**
 * Impact (C, A, I)
 */
var Impact;
(function (Impact) {
    Impact["NOT_DEFINED"] = "NOT_DEFINED";
    Impact["NONE"] = "NONE";
    Impact["LOW"] = "LOW";
    Impact["HIGH"] = "HIGH";
})(Impact || (Impact = {}));
/******************************************************************************/
/**                               Temporal Metrics                            */
/******************************************************************************/
/**
 * Exploit Code Maturity (E)
 */
var ExploitCodeMaturity;
(function (ExploitCodeMaturity) {
    ExploitCodeMaturity["NOT_DEFINED"] = "NOT_DEFINED";
    ExploitCodeMaturity["UNPROVEN"] = "UNPROVEN";
    ExploitCodeMaturity["FUNCTIONAL"] = "FUNCTIONAL";
    ExploitCodeMaturity["PROOF_OF_CONCEPT"] = "PROOF_OF_CONCEPT";
    ExploitCodeMaturity["HIGH"] = "HIGH";
})(ExploitCodeMaturity || (ExploitCodeMaturity = {}));
/**
 * Remediation Level (RL)
 */
var RemediationLevel;
(function (RemediationLevel) {
    RemediationLevel["NOT_DEFINED"] = "NOT_DEFINED";
    RemediationLevel["OFFICIAL_FIX"] = "OFFICIAL_FIX";
    RemediationLevel["TEMPORARY_FIX"] = "TEMPORARY_FIX";
    RemediationLevel["WORKAROUND"] = "WORKAROUND";
    RemediationLevel["UNAVAILABLE"] = "UNAVAILABLE";
})(RemediationLevel || (RemediationLevel = {}));
/**
 * Report Confidence (RC)
 */
var ReportConfidence;
(function (ReportConfidence) {
    ReportConfidence["NOT_DEFINED"] = "NOT_DEFINED";
    ReportConfidence["UNKNOWN"] = "UNKNOWN";
    ReportConfidence["REASONABLE"] = "REASONABLE";
    ReportConfidence["CONFIRMED"] = "CONFIRMED";
})(ReportConfidence || (ReportConfidence = {}));
/******************************************************************************/
/**                            Environmental Metrics                          */
/******************************************************************************/
/**
 * Security Requirements (CR, IR, AR)
 */
var SecurityRequirements;
(function (SecurityRequirements) {
    SecurityRequirements["NOT_DEFINED"] = "NOT_DEFINED";
    SecurityRequirements["LOW"] = "LOW";
    SecurityRequirements["MEDIUM"] = "MEDIUM";
    SecurityRequirements["HIGH"] = "HIGH";
})(SecurityRequirements || (SecurityRequirements = {}));

/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v3.1/specification-document
 */
class CVSS31Calculator {
    constructor() {
        this.baseScore = 0;
        this.impactSubScore = 0;
        this.exploitabilitySubScore = 0;
        this.temporalScore = 0;
        this.environmentalScore = 0;
        this.cvss3Info = {
            AttackVector: AttackVector.NOT_DEFINED,
            AttackComplexity: AttackComplexity.NOT_DEFINED,
            PrivilegesRequired: PrivilegesRequired.NOT_DEFINED,
            UserInteraction: UserInteraction.NOT_DEFINED,
            Scope: Scope.NOT_DEFINED,
            ConfidentialityImpact: Impact.NOT_DEFINED,
            IntegrityImpact: Impact.NOT_DEFINED,
            AvailabilityImpact: Impact.NOT_DEFINED,
            ExploitCodeMaturity: ExploitCodeMaturity.NOT_DEFINED,
            RemediationLevel: RemediationLevel.NOT_DEFINED,
            ReportConfidence: ReportConfidence.NOT_DEFINED,
            ConfidentialityRequirement: SecurityRequirements.NOT_DEFINED,
            IntegrityRequirement: SecurityRequirements.NOT_DEFINED,
            AvailabilityRequirement: SecurityRequirements.NOT_DEFINED
        };
    }
    /******************************************************************************/
    /**                             Public Methods                                */
    /******************************************************************************/
    /**
     * Compute the CVSS 3 base score from the parsed CVSS 2 Vector
     * @param cvss3Info the parsed CVSS 3 Vector
     * @returns the base score
     */
    computeBaseScore(cvss3Info) {
        this.cvss3Info = cvss3Info;
        const impactSubScore = this.computeImpactSubScore();
        const exploitabilitySubScore = this.computeExploitabilitySubScore();
        if (impactSubScore <= 0)
            return 0.0;
        let baseScore = 0.0;
        if (Scope.UNCHANGED) {
            baseScore = Math.min(impactSubScore + exploitabilitySubScore, 10);
        }
        else if (Scope.CHANGED) {
            baseScore = Math.min(1.08 * (impactSubScore + exploitabilitySubScore), 10);
        }
        this.baseScore = baseScore;
        return this.baseScore;
    }
    /**
     * Compute the CVSS 3 temporal score from the parsed CVSS 3 Vector
     * @param cvss3Info the parsed CVSS 3 Vector
     * @returns the temporal score
     */
    computeTemporalScore(cvss3Info) {
        this.cvss3Info = cvss3Info;
        if (this.baseScore == undefined) {
            this.computeBaseScore(cvss3Info);
        }
        const exploitCodeMaturity = this.computeExploitCodeMaturity();
        const remediationLevel = this.computeRemediationLevel();
        const reportConfidence = this.computeReportConfidence();
        const temporalScore = roundUp(this.baseScore * exploitCodeMaturity * remediationLevel * reportConfidence);
        this.temporalScore = temporalScore;
        return temporalScore;
    }
    /**
     * Compute the CVSS 3 environmental score from the parsed CVSS 3 Vector
     * @param cvss3Info the parsed CVSS 3 Vector
     * @returns the temporal score
     */
    computeEnvironmentalScore(cvss3Info) {
        this.cvss3Info = cvss3Info;
        const modifiedImpactSubScore = this.computeModifiedImpactSubScore();
        const modifiedExploitabilitySubScore = this.computeModifiedExploitabilitySubScore();
        const exploitCodeMaturity = this.computeExploitCodeMaturity();
        const remediationLevel = this.computeRemediationLevel();
        const reportConfidence = this.computeRemediationLevel();
        if (modifiedImpactSubScore <= 0)
            return 0.0;
        let environmentalScore = 0.0;
        if (this.cvss3Info.Scope == Scope.UNCHANGED) {
            environmentalScore = roundUp(roundUp(Math.min(modifiedImpactSubScore + modifiedExploitabilitySubScore, 10.0)) *
                exploitCodeMaturity *
                remediationLevel *
                reportConfidence);
        }
        else if (this.cvss3Info.Scope == Scope.CHANGED) {
            environmentalScore = roundUp(roundUp(Math.min(1.08 * (modifiedImpactSubScore + modifiedExploitabilitySubScore), 10.0)) *
                exploitCodeMaturity *
                remediationLevel *
                reportConfidence);
        }
        this.environmentalScore = environmentalScore;
        return environmentalScore;
    }
    /**
     * Returns the base score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the base score
     */
    getBaseScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.baseScore);
        return this.baseScore;
    }
    /**
     * Returns the temporal score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the temporal score
     */
    getTemporalScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.temporalScore);
        return this.temporalScore;
    }
    /**
     * Returns the environmental score
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the environmental score
     */
    getEnvironmentalScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.environmentalScore);
        return this.environmentalScore;
    }
    /**
     * Returns the impact subscore
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the impact subscore
     */
    getImpactSubScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.impactSubScore);
        return this.impactSubScore;
    }
    /**
     * Returns the exploitability subscore
     * @param roundUpVal Whether or not to round up the floating point value up to its nearest multiple of 0.1 (i.e. to one decimal place).
     * @returns the exploitability subscore
     */
    getExploitabilitySubScore(roundUpVal) {
        if (roundUpVal)
            return roundUp(this.exploitabilitySubScore);
        return this.exploitabilitySubScore;
    }
    /******************************************************************************/
    /**                          Base Score calculation                           */
    /******************************************************************************/
    computeExploitabilitySubScore() {
        const attackVector = this.computeAttackVector();
        const attackComplexity = this.computeAttackComplexity();
        const privilegesRequired = this.computePrivilegesRequired();
        const userInteraction = this.computeUserInteraction();
        const exploitabilitySubScore = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;
        this.exploitabilitySubScore = exploitabilitySubScore;
        return exploitabilitySubScore;
    }
    computeImpactSubScore() {
        const baseImpactScore = this.computeBaseImpactSubScore();
        if (this.cvss3Info.Scope == Scope.UNCHANGED) {
            const impactSubScore = 6.42 * baseImpactScore;
            this.impactSubScore = impactSubScore;
            return impactSubScore;
        }
        const impactSubScore = 7.52 * (baseImpactScore - 0.029) - 3.25 * Math.pow(baseImpactScore - 0.02, 15);
        this.impactSubScore = impactSubScore;
        return impactSubScore;
    }
    computeBaseImpactSubScore() {
        const confidentialityImpact = this.computeConfidentialityImpact();
        const integrityImpact = this.computeIntegrityImpact();
        const availabilityImpact = this.computeAvailabilityImpact();
        // Compute and return the base impact subscore (called ISC_Base) in the specification.
        return 1 - (1 - confidentialityImpact) * (1 - integrityImpact) * (1 - availabilityImpact);
    }
    computeConfidentialityImpact() {
        switch (this.cvss3Info.ConfidentialityImpact) {
            case Impact.NONE:
                return 0.0;
            case Impact.LOW:
                return 0.22;
            case Impact.HIGH:
                return 0.56;
            default:
                return 0.0;
        }
    }
    computeIntegrityImpact() {
        switch (this.cvss3Info.IntegrityImpact) {
            case Impact.NONE:
                return 0.0;
            case Impact.LOW:
                return 0.22;
            case Impact.HIGH:
                return 0.56;
            default:
                return 0.0;
        }
    }
    computeAvailabilityImpact() {
        switch (this.cvss3Info.AvailabilityImpact) {
            case Impact.NONE:
                return 0.0;
            case Impact.LOW:
                return 0.22;
            case Impact.HIGH:
                return 0.56;
            default:
                return 0.0;
        }
    }
    computeAttackVector() {
        switch (this.cvss3Info.AttackVector) {
            case AttackVector.NETWORK:
                return 0.85;
            case AttackVector.ADJACENT_NETWORK:
                return 0.62;
            case AttackVector.LOCAL:
                return 0.55;
            case AttackVector.PHYSICAL:
                return 0.2;
            default:
                return 0.0;
        }
    }
    computeAttackComplexity() {
        switch (this.cvss3Info.AttackComplexity) {
            case AttackComplexity.LOW:
                return 0.77;
            case AttackComplexity.HIGH:
                return 0.44;
            default:
                return 0.0;
        }
    }
    computePrivilegesRequired() {
        switch (this.cvss3Info.PrivilegesRequired) {
            case PrivilegesRequired.NONE:
                return 0.85;
            case PrivilegesRequired.LOW:
                return this.cvss3Info.Scope == Scope.CHANGED ? 0.68 : 0.62;
            case PrivilegesRequired.HIGH:
                return this.cvss3Info.Scope == Scope.CHANGED ? 0.5 : 0.27;
            default:
                return 0.0;
        }
    }
    computeUserInteraction() {
        switch (this.cvss3Info.UserInteraction) {
            case UserInteraction.NONE:
                return 0.85;
            case UserInteraction.REQUIRED:
                return 0.62;
            default:
                return 0.0;
        }
    }
    /******************************************************************************/
    /**                        Temporal Score calculation                         */
    /******************************************************************************/
    computeExploitCodeMaturity() {
        switch (this.cvss3Info.ExploitCodeMaturity) {
            case ExploitCodeMaturity.NOT_DEFINED:
                return 1.0;
            case ExploitCodeMaturity.HIGH:
                return 1.0;
            case ExploitCodeMaturity.FUNCTIONAL:
                return 0.97;
            case ExploitCodeMaturity.PROOF_OF_CONCEPT:
                return 0.94;
            case ExploitCodeMaturity.UNPROVEN:
                return 0.91;
            default:
                return 1.0;
        }
    }
    computeRemediationLevel() {
        switch (this.cvss3Info.RemediationLevel) {
            case RemediationLevel.NOT_DEFINED:
                return 1.0;
            case RemediationLevel.UNAVAILABLE:
                return 1.0;
            case RemediationLevel.WORKAROUND:
                return 0.97;
            case RemediationLevel.TEMPORARY_FIX:
                return 0.96;
            case RemediationLevel.OFFICIAL_FIX:
                return 0.95;
            default:
                return 1.0;
        }
    }
    computeReportConfidence() {
        switch (this.cvss3Info.ReportConfidence) {
            case ReportConfidence.NOT_DEFINED:
                return 1.0;
            case ReportConfidence.CONFIRMED:
                return 1.0;
            case ReportConfidence.REASONABLE:
                return 0.96;
            case ReportConfidence.UNKNOWN:
                return 0.92;
            default:
                return 1.0;
        }
    }
    /******************************************************************************/
    /**                      Environmental Score calculation                      */
    /******************************************************************************/
    computeModifiedExploitabilitySubScore() {
        const attackVector = this.computeAttackVector();
        const attackComplexity = this.computeAttackComplexity();
        const privilegesRequired = this.computePrivilegesRequired();
        const userInteraction = this.computeUserInteraction();
        const exploitabilitySubScore = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;
        return exploitabilitySubScore;
    }
    computeModifiedImpactSubScore() {
        const iscModified = this.computeIscModified();
        if (this.cvss3Info.Scope === Scope.UNCHANGED) {
            return 6.42 * iscModified;
        }
        else if (this.cvss3Info.Scope === Scope.CHANGED) {
            return 7.52 * (iscModified - 0.029) - 3.25 * Math.pow(iscModified * 0.9731 - 0.02, 15); // this is the only line that differs from CVSS 3
        }
        else {
            return 0.0;
        }
    }
    computeIscModified() {
        const modifiedConfidentialityImpact = this.computeConfidentialityImpact();
        const modifiedIntegrityImpact = this.computeIntegrityImpact();
        const modifiedAvailabilityImpact = this.computeAvailabilityImpact();
        const confidenialityRequirement = this.computeConfidentialityRequirement();
        const integrityRequirement = this.computeIntegrityRequirement();
        const availabilityRequirement = this.computeAvailabilityRequirement();
        const isc_modified = (1 - modifiedConfidentialityImpact * confidenialityRequirement) *
            (1 - modifiedIntegrityImpact * integrityRequirement) *
            (1 - modifiedAvailabilityImpact * availabilityRequirement);
        return Math.min(1 - isc_modified, 0.915);
    }
    computeConfidentialityRequirement() {
        switch (this.cvss3Info.ConfidentialityRequirement) {
            case SecurityRequirements.NOT_DEFINED:
                return 1.0;
            case SecurityRequirements.HIGH:
                return 1.5;
            case SecurityRequirements.MEDIUM:
                return 1.0;
            case SecurityRequirements.LOW:
                return 0.5;
            default:
                return 1.0;
        }
    }
    computeAvailabilityRequirement() {
        switch (this.cvss3Info.AvailabilityRequirement) {
            case SecurityRequirements.NOT_DEFINED:
                return 1.0;
            case SecurityRequirements.HIGH:
                return 1.5;
            case SecurityRequirements.MEDIUM:
                return 1.0;
            case SecurityRequirements.LOW:
                return 0.5;
            default:
                return 1.0;
        }
    }
    computeIntegrityRequirement() {
        switch (this.cvss3Info.IntegrityRequirement) {
            case SecurityRequirements.NOT_DEFINED:
                return 1.0;
            case SecurityRequirements.HIGH:
                return 1.5;
            case SecurityRequirements.MEDIUM:
                return 1.0;
            case SecurityRequirements.LOW:
                return 0.5;
            default:
                return 1.0;
        }
    }
}

/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v2/guide
 */
class CVSS2VectorParser {
    /**
     * Parse CVSS 2 Access Vector
     */
    parseAV(part) {
        switch (part) {
            case 'L':
                return AccessVector.LOCAL;
            case 'A':
                return AccessVector.ADJACENT_NETWORK;
            case 'N':
                return AccessVector.NETWORK;
            default:
                return AccessVector.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Access Complexity
     */
    parseAC(part) {
        switch (part) {
            case 'H':
                return AccessComplexity.HIGH;
            case 'M':
                return AccessComplexity.MEDIUM;
            case 'L':
                return AccessComplexity.LOW;
            default:
                return AccessComplexity.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Authentication
     */
    parseAu(part) {
        switch (part) {
            case 'M':
                return Authentication.MULTIPLE;
            case 'S':
                return Authentication.SINGLE;
            case 'N':
                return Authentication.NONE;
            default:
                return Authentication.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Confidentiality, Availability, Integrity Impact
     */
    parseImact(part) {
        switch (part) {
            case 'N':
                return Impact$2.NONE;
            case 'P':
                return Impact$2.PARTIAL;
            case 'C':
                return Impact$2.COMPLETE;
            default:
                return Impact$2.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Exploitability
     */
    parseE(part) {
        switch (part) {
            case 'U':
                return Exploitability.UNPROVEN;
            case 'POC':
                return Exploitability.PROOF_OF_CONCEPT;
            case 'F':
                return Exploitability.FUNCTIONAL;
            case 'H':
                return Exploitability.HIGH;
            default:
                return Exploitability.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Remediation Level
     */
    parseRL(part) {
        switch (part) {
            case 'OF':
                return RemediationLevel$2.OFFICIAL_FIX;
            case 'TF':
                return RemediationLevel$2.TEMPORARY_FIX;
            case 'W':
                return RemediationLevel$2.WORKAROUND;
            case 'U':
                return RemediationLevel$2.UNAVAILABLE;
            default:
                return RemediationLevel$2.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Report Confidence
     */
    parseRC(part) {
        switch (part) {
            case 'UC':
                return ReportConfidence$2.UNCONFIRMED;
            case 'UR':
                return ReportConfidence$2.UNCORROBORATED;
            case 'C':
                return ReportConfidence$2.CONFIRMED;
            default:
                return ReportConfidence$2.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Colleteral Damange Potential
     */
    parseCDP(part) {
        switch (part) {
            case 'N':
                return CollateralDamagePotential.NONE;
            case 'L':
                return CollateralDamagePotential.LOW;
            case 'LM':
                return CollateralDamagePotential.LOW_MEDIUM;
            case 'MH':
                return CollateralDamagePotential.MEDIUM_HIGH;
            case 'H':
                return CollateralDamagePotential.HIGH;
            default:
                return CollateralDamagePotential.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Target Distribution
     */
    parseTD(part) {
        switch (part) {
            case 'N':
                return TargetDistribution.NONE;
            case 'L':
                return TargetDistribution.LOW;
            case 'M':
                return TargetDistribution.MEDIUM;
            case 'H':
                return TargetDistribution.HIGH;
            default:
                return TargetDistribution.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Security Requirements (CR, IR, AR)
     */
    parseSecurityRequirement(part) {
        switch (part) {
            case 'L':
                return SecurityRequirements$2.LOW;
            case 'M':
                return SecurityRequirements$2.MEDIUM;
            case 'H':
                return SecurityRequirements$2.HIGH;
            default:
                return SecurityRequirements$2.NOT_DEFINED;
        }
    }
    /**
     * Parses a CVSS 2 vector
     * @param vector CVSS 2 vector String
     * @returns Parsed CVSS 2 Vector
     */
    parse(vector) {
        // Split the CVSS 2 string
        const parts = vector.split('/');
        // If the first part is the cvss version, then remove it
        if (parts[0] == 'CVSS') {
            parts.shift();
        }
        const parsedVector = {
            AccessVector: AccessVector.NOT_DEFINED,
            AccessComplexity: AccessComplexity.NOT_DEFINED,
            Authentication: Authentication.NOT_DEFINED,
            ConfidentialityImpact: Impact$2.NOT_DEFINED,
            IntegrityImpact: Impact$2.NOT_DEFINED,
            AvailabilityImpact: Impact$2.NOT_DEFINED,
            Exploitability: Exploitability.NOT_DEFINED,
            RemediationLevel: RemediationLevel$2.NOT_DEFINED,
            ReportConfidence: ReportConfidence$2.NOT_DEFINED,
            CollateralDamagePotential: CollateralDamagePotential.NOT_DEFINED,
            TargetDistribution: TargetDistribution.NOT_DEFINED,
            ConfidentialityRequirement: SecurityRequirements$2.NOT_DEFINED,
            IntegrityRequirement: SecurityRequirements$2.NOT_DEFINED,
            AvailabilityRequirement: SecurityRequirements$2.NOT_DEFINED
        };
        // Parse the cvss 2 vector parts
        for (const part of parts) {
            const partsArray = part.split(':');
            const partId = partsArray[0];
            const partValue = partsArray[1];
            switch (partId) {
                case 'AV':
                    parsedVector.AccessVector = this.parseAV(partValue);
                    break;
                case 'AC':
                    parsedVector.AccessComplexity = this.parseAC(partValue);
                    break;
                case 'Au':
                    parsedVector.Authentication = this.parseAu(partValue);
                    break;
                case 'C':
                    parsedVector.ConfidentialityImpact = this.parseImact(partValue);
                    break;
                case 'I':
                    parsedVector.IntegrityImpact = this.parseImact(partValue);
                    break;
                case 'A':
                    parsedVector.AvailabilityImpact = this.parseImact(partValue);
                    break;
                case 'E':
                    parsedVector.Exploitability = this.parseE(partValue);
                    break;
                case 'RL':
                    parsedVector.RemediationLevel = this.parseRL(partValue);
                    break;
                case 'RC':
                    parsedVector.ReportConfidence = this.parseRC(partValue);
                    break;
                case 'CDP':
                    parsedVector.CollateralDamagePotential = this.parseCDP(partValue);
                    break;
                case 'TD':
                    parsedVector.TargetDistribution = this.parseTD(partValue);
                    break;
                case 'CR':
                    parsedVector.ConfidentialityRequirement =
                        this.parseSecurityRequirement(partValue);
                    break;
                case 'IR':
                    parsedVector.IntegrityRequirement = this.parseSecurityRequirement(partValue);
                    break;
                case 'AR':
                    parsedVector.AvailabilityRequirement = this.parseSecurityRequirement(partValue);
                    break;
            }
        }
        return parsedVector;
    }
}

/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v3.0/specification-document
 */
class CVSS3VectorParser {
    /**
     * Parse CVSS 3 Attack Vector
     */
    parseAV(part) {
        switch (part) {
            case 'L':
                return AttackVector$1.LOCAL;
            case 'A':
                return AttackVector$1.ADJACENT_NETWORK;
            case 'N':
                return AttackVector$1.NETWORK;
            case 'P':
                return AttackVector$1.PHYSICAL;
            default:
                return AttackVector$1.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3 Attack Complexity
     */
    parseAC(part) {
        switch (part) {
            case 'L':
                return AttackComplexity$1.LOW;
            case 'H':
                return AttackComplexity$1.HIGH;
            default:
                return AttackComplexity$1.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3 Privileges Required
     */
    parsePR(part) {
        switch (part) {
            case 'N':
                return PrivilegesRequired$1.NONE;
            case 'L':
                return PrivilegesRequired$1.LOW;
            case 'H':
                return PrivilegesRequired$1.HIGH;
            default:
                return PrivilegesRequired$1.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3 User Interaction
     */
    parseUI(part) {
        switch (part) {
            case 'N':
                return UserInteraction$1.NONE;
            case 'R':
                return UserInteraction$1.REQUIRED;
            default:
                return UserInteraction$1.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3 Scope
     */
    parseS(part) {
        switch (part) {
            case 'U':
                return Scope$1.UNCHANGED;
            case 'C':
                return Scope$1.CHANGED;
            default:
                return Scope$1.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3 Confidentiality, Availability, Integrity Impact
     */
    parseImact(part) {
        switch (part) {
            case 'N':
                return Impact$1.NONE;
            case 'H':
                return Impact$1.HIGH;
            case 'L':
                return Impact$1.LOW;
            default:
                return Impact$1.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3 Exploit Code Maturity
     */
    parseE(part) {
        switch (part) {
            case 'X':
                return ExploitCodeMaturity$1.NOT_DEFINED;
            case 'H':
                return ExploitCodeMaturity$1.HIGH;
            case 'F':
                return ExploitCodeMaturity$1.FUNCTIONAL;
            case 'P':
                return ExploitCodeMaturity$1.PROOF_OF_CONCEPT;
            case 'U':
                return ExploitCodeMaturity$1.UNPROVEN;
            default:
                return ExploitCodeMaturity$1.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3 Exploit Code Maturity
     */
    parseRL(part) {
        switch (part) {
            case 'X':
                return RemediationLevel$1.NOT_DEFINED;
            case 'U':
                return RemediationLevel$1.UNAVAILABLE;
            case 'W':
                return RemediationLevel$1.WORKAROUND;
            case 'T':
                return RemediationLevel$1.TEMPORARY_FIX;
            case 'O':
                return RemediationLevel$1.OFFICIAL_FIX;
            default:
                return RemediationLevel$1.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3 Report Confidence
     */
    parseRC(part) {
        switch (part) {
            case 'X':
                return ReportConfidence$1.NOT_DEFINED;
            case 'C':
                return ReportConfidence$1.CONFIRMED;
            case 'R':
                return ReportConfidence$1.REASONABLE;
            case 'U':
                return ReportConfidence$1.UNKNOWN;
            default:
                return ReportConfidence$1.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Security Requirements (CR, IR, AR)
     */
    parseSecurityRequirement(part) {
        switch (part) {
            case 'X':
                return SecurityRequirements$1.NOT_DEFINED;
            case 'L':
                return SecurityRequirements$1.LOW;
            case 'M':
                return SecurityRequirements$1.MEDIUM;
            case 'H':
                return SecurityRequirements$1.HIGH;
            default:
                return SecurityRequirements$1.NOT_DEFINED;
        }
    }
    /**
     * Parses a CVSS 3 vector
     * @param vector CVSS 3 vector String
     * @returns Parsed CVSS 3 Vector
     */
    parse(vector) {
        // Split the cvss string
        const parts = vector.split('/');
        // If the first part is the cvss version, then remove it
        if (parts[0] == 'CVSS') {
            parts.shift();
        }
        const parsedVector = {
            AttackVector: AttackVector$1.NOT_DEFINED,
            AttackComplexity: AttackComplexity$1.NOT_DEFINED,
            PrivilegesRequired: PrivilegesRequired$1.NOT_DEFINED,
            UserInteraction: UserInteraction$1.NOT_DEFINED,
            Scope: Scope$1.NOT_DEFINED,
            ConfidentialityImpact: Impact$1.NOT_DEFINED,
            IntegrityImpact: Impact$1.NOT_DEFINED,
            AvailabilityImpact: Impact$1.NOT_DEFINED,
            ExploitCodeMaturity: ExploitCodeMaturity$1.NOT_DEFINED,
            RemediationLevel: RemediationLevel$1.NOT_DEFINED,
            ReportConfidence: ReportConfidence$1.NOT_DEFINED,
            ConfidentialityRequirement: SecurityRequirements$1.NOT_DEFINED,
            IntegrityRequirement: SecurityRequirements$1.NOT_DEFINED,
            AvailabilityRequirement: SecurityRequirements$1.NOT_DEFINED
        };
        // Parse the CVSS 3 vector parts
        for (const part of parts) {
            const partsArray = part.split(':');
            const partId = partsArray[0];
            const partValue = partsArray[1];
            switch (partId) {
                case 'AV':
                    parsedVector.AttackVector = this.parseAV(partValue);
                    break;
                case 'AC':
                    parsedVector.AttackComplexity = this.parseAC(partValue);
                    break;
                case 'PR':
                    parsedVector.PrivilegesRequired = this.parsePR(partValue);
                    break;
                case 'UI':
                    parsedVector.UserInteraction = this.parseUI(partValue);
                    break;
                case 'S':
                    parsedVector.Scope = this.parseS(partValue);
                    break;
                case 'C':
                    parsedVector.ConfidentialityImpact = this.parseImact(partValue);
                    break;
                case 'I':
                    parsedVector.IntegrityImpact = this.parseImact(partValue);
                    break;
                case 'A':
                    parsedVector.AvailabilityImpact = this.parseImact(partValue);
                    break;
                case 'E':
                    parsedVector.ExploitCodeMaturity = this.parseE(partValue);
                    break;
                case 'RL':
                    parsedVector.RemediationLevel = this.parseRL(partValue);
                    break;
                case 'RC':
                    parsedVector.ReportConfidence = this.parseRC(partValue);
                    break;
                case 'CR':
                    parsedVector.ConfidentialityRequirement =
                        this.parseSecurityRequirement(partValue);
                    break;
                case 'IR':
                    parsedVector.IntegrityRequirement = this.parseSecurityRequirement(partValue);
                    break;
                case 'AR':
                    parsedVector.AvailabilityRequirement = this.parseSecurityRequirement(partValue);
                    break;
            }
        }
        return parsedVector;
    }
}

/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v3.1/specification-document
 */
class CVSS31VectorParser {
    /**
     * Parse CVSS 3.1 Attack Vector
     */
    parseAV(part) {
        switch (part) {
            case 'L':
                return AttackVector.LOCAL;
            case 'A':
                return AttackVector.ADJACENT_NETWORK;
            case 'N':
                return AttackVector.NETWORK;
            case 'P':
                return AttackVector.PHYSICAL;
            default:
                return AttackVector.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3.1 Attack Complexity
     */
    parseAC(part) {
        switch (part) {
            case 'L':
                return AttackComplexity.LOW;
            case 'H':
                return AttackComplexity.HIGH;
            default:
                return AttackComplexity.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3.1 Privileges Required
     */
    parsePR(part) {
        switch (part) {
            case 'N':
                return PrivilegesRequired.NONE;
            case 'L':
                return PrivilegesRequired.LOW;
            case 'H':
                return PrivilegesRequired.HIGH;
            default:
                return PrivilegesRequired.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3.1 User Interaction
     */
    parseUI(part) {
        switch (part) {
            case 'N':
                return UserInteraction.NONE;
            case 'R':
                return UserInteraction.REQUIRED;
            default:
                return UserInteraction.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3.1 Scope
     */
    parseS(part) {
        switch (part) {
            case 'U':
                return Scope.UNCHANGED;
            case 'C':
                return Scope.CHANGED;
            default:
                return Scope.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3.1 Confidentiality, Availability, Integrity Impact
     */
    parseImact(part) {
        switch (part) {
            case 'N':
                return Impact.NONE;
            case 'H':
                return Impact.HIGH;
            case 'L':
                return Impact.LOW;
            default:
                return Impact.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3.1 Exploit Code Maturity
     */
    parseE(part) {
        switch (part) {
            case 'X':
                return ExploitCodeMaturity.NOT_DEFINED;
            case 'H':
                return ExploitCodeMaturity.HIGH;
            case 'F':
                return ExploitCodeMaturity.FUNCTIONAL;
            case 'P':
                return ExploitCodeMaturity.PROOF_OF_CONCEPT;
            case 'U':
                return ExploitCodeMaturity.UNPROVEN;
            default:
                return ExploitCodeMaturity.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3.1 Exploit Code Maturity
     */
    parseRL(part) {
        switch (part) {
            case 'X':
                return RemediationLevel.NOT_DEFINED;
            case 'U':
                return RemediationLevel.UNAVAILABLE;
            case 'W':
                return RemediationLevel.WORKAROUND;
            case 'T':
                return RemediationLevel.TEMPORARY_FIX;
            case 'O':
                return RemediationLevel.OFFICIAL_FIX;
            default:
                return RemediationLevel.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 3.1 Report Confidence
     */
    parseRC(part) {
        switch (part) {
            case 'X':
                return ReportConfidence.NOT_DEFINED;
            case 'C':
                return ReportConfidence.CONFIRMED;
            case 'R':
                return ReportConfidence.REASONABLE;
            case 'U':
                return ReportConfidence.UNKNOWN;
            default:
                return ReportConfidence.NOT_DEFINED;
        }
    }
    /**
     * Parse CVSS 2 Security Requirements (CR, IR, AR)
     */
    parseSecurityRequirement(part) {
        switch (part) {
            case 'X':
                return SecurityRequirements.NOT_DEFINED;
            case 'L':
                return SecurityRequirements.LOW;
            case 'M':
                return SecurityRequirements.MEDIUM;
            case 'H':
                return SecurityRequirements.HIGH;
            default:
                return SecurityRequirements.NOT_DEFINED;
        }
    }
    /**
     * Parses a CVSS 3.1 vector
     * @param vector CVSS 3.1 vector String
     * @returns Parsed CVSS 3.1 Vector
     */
    parse(vector) {
        // Split the cvss string
        const parts = vector.split('/');
        // If the first part is the cvss version, then remove it
        if (parts[0] == 'CVSS') {
            parts.shift();
        }
        const parsedVector = {
            AttackVector: AttackVector.NOT_DEFINED,
            AttackComplexity: AttackComplexity.NOT_DEFINED,
            PrivilegesRequired: PrivilegesRequired.NOT_DEFINED,
            UserInteraction: UserInteraction.NOT_DEFINED,
            Scope: Scope.NOT_DEFINED,
            ConfidentialityImpact: Impact.NOT_DEFINED,
            IntegrityImpact: Impact.NOT_DEFINED,
            AvailabilityImpact: Impact.NOT_DEFINED,
            ExploitCodeMaturity: ExploitCodeMaturity.NOT_DEFINED,
            RemediationLevel: RemediationLevel.NOT_DEFINED,
            ReportConfidence: ReportConfidence.NOT_DEFINED,
            ConfidentialityRequirement: SecurityRequirements.NOT_DEFINED,
            IntegrityRequirement: SecurityRequirements.NOT_DEFINED,
            AvailabilityRequirement: SecurityRequirements.NOT_DEFINED
        };
        // Parse the CVSS 3.1 vector parts
        for (const part of parts) {
            const partsArray = part.split(':');
            const partId = partsArray[0];
            const partValue = partsArray[1];
            switch (partId) {
                case 'AV':
                    parsedVector.AttackVector = this.parseAV(partValue);
                    break;
                case 'AC':
                    parsedVector.AttackComplexity = this.parseAC(partValue);
                    break;
                case 'PR':
                    parsedVector.PrivilegesRequired = this.parsePR(partValue);
                    break;
                case 'UI':
                    parsedVector.UserInteraction = this.parseUI(partValue);
                    break;
                case 'S':
                    parsedVector.Scope = this.parseS(partValue);
                    break;
                case 'C':
                    parsedVector.ConfidentialityImpact = this.parseImact(partValue);
                    break;
                case 'I':
                    parsedVector.IntegrityImpact = this.parseImact(partValue);
                    break;
                case 'A':
                    parsedVector.AvailabilityImpact = this.parseImact(partValue);
                    break;
                case 'E':
                    parsedVector.ExploitCodeMaturity = this.parseE(partValue);
                    break;
                case 'RL':
                    parsedVector.RemediationLevel = this.parseRL(partValue);
                    break;
                case 'RC':
                    parsedVector.ReportConfidence = this.parseRC(partValue);
                    break;
                case 'CR':
                    parsedVector.ConfidentialityRequirement =
                        this.parseSecurityRequirement(partValue);
                    break;
                case 'IR':
                    parsedVector.IntegrityRequirement = this.parseSecurityRequirement(partValue);
                    break;
                case 'AR':
                    parsedVector.AvailabilityRequirement = this.parseSecurityRequirement(partValue);
                    break;
            }
        }
        return parsedVector;
    }
}

function createCVSS2Parser() {
    return new CVSS2VectorParser();
}
function createCVSS3Parser() {
    return new CVSS3VectorParser();
}
function createCVSS31Parser() {
    return new CVSS31VectorParser();
}
function createCVSS2Calculator() {
    return new CVSS2Calculator();
}
function createCVSS3Calculator() {
    return new CVSS3Calculator();
}
function createCVSS31Calculator() {
    return new CVSS31Calculator();
}

exports.createCVSS2Calculator = createCVSS2Calculator;
exports.createCVSS2Parser = createCVSS2Parser;
exports.createCVSS31Calculator = createCVSS31Calculator;
exports.createCVSS31Parser = createCVSS31Parser;
exports.createCVSS3Calculator = createCVSS3Calculator;
exports.createCVSS3Parser = createCVSS3Parser;
