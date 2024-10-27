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
export declare enum AccessVector {
    NOT_DEFINED = "NOT_DEFINED",
    LOCAL = "LOCAL",
    ADJACENT_NETWORK = "ADJACENT_NETWORK",
    NETWORK = "NETWORK"
}
/**
 * Access Complexity (AC)
 */
export declare enum AccessComplexity {
    NOT_DEFINED = "NOT_DEFINED",
    LOW = "LOW",
    MEDIUM = "MEDIUM",
    HIGH = "HIGH"
}
/**
 * Authentication (Au)
 */
export declare enum Authentication {
    NOT_DEFINED = "NOT_DEFINED",
    MULTIPLE = "MULTIPLE",
    SINGLE = "SINGLE",
    NONE = "NONE"
}
/**
 * Impact (C, A, I)
 */
export declare enum Impact {
    NOT_DEFINED = "NOT_DEFINED",
    NONE = "NONE",
    PARTIAL = "PARTIAL",
    COMPLETE = "COMPLETE"
}
/******************************************************************************/
/**                               Temporal Metrics                            */
/******************************************************************************/
/**
 * Exploitability (E)
 */
export declare enum Exploitability {
    NOT_DEFINED = "NOT_DEFINED",
    UNPROVEN = "UNPROVEN",
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT",
    FUNCTIONAL = "FUNCTIONAL",
    HIGH = "HIGH"
}
/**
 * Remediation Level (RL)
 */
export declare enum RemediationLevel {
    NOT_DEFINED = "NOT_DEFINED",
    OFFICIAL_FIX = "OFFICIAL_FIX",
    TEMPORARY_FIX = "TEMPORARY_FIX",
    WORKAROUND = "WORKAROUND",
    UNAVAILABLE = "UNAVAILABLE"
}
/**
 * Report Confidence (RC)
 */
export declare enum ReportConfidence {
    NOT_DEFINED = "NOT_DEFINED",
    UNCONFIRMED = "UNCONFIRMED",
    UNCORROBORATED = "UNCORROBORATED",
    CONFIRMED = "CONFIRMED"
}
/******************************************************************************/
/**                            Environmental Metrics                          */
/******************************************************************************/
/**
 * Collateral Damage Potential (CDP)
 */
export declare enum CollateralDamagePotential {
    NOT_DEFINED = "NOT_DEFINED",
    NONE = "NONE",
    LOW = "LOW",
    LOW_MEDIUM = "LOW_MEDIUM",
    MEDIUM_HIGH = "MEDIUM_HIGH",
    HIGH = "HIGH"
}
/**
 * Target Distribution (TD)
 */
export declare enum TargetDistribution {
    NOT_DEFINED = "NOT_DEFINED",
    NONE = "NONE",
    LOW = "LOW",
    MEDIUM = "MEDIUM",
    HIGH = "HIGH"
}
/**
 * Security Requirements (CR, IR, AR)
 */
export declare enum SecurityRequirements {
    NOT_DEFINED = "NOT_DEFINED",
    LOW = "LOW",
    MEDIUM = "MEDIUM",
    HIGH = "HIGH"
}
export interface CVSS2Info {
    AccessVector: AccessVector;
    AccessComplexity: AccessComplexity;
    Authentication: Authentication;
    ConfidentialityImpact: Impact;
    IntegrityImpact: Impact;
    AvailabilityImpact: Impact;
    Exploitability: Exploitability;
    RemediationLevel: RemediationLevel;
    ReportConfidence: ReportConfidence;
    CollateralDamagePotential: CollateralDamagePotential;
    TargetDistribution: TargetDistribution;
    ConfidentialityRequirement: SecurityRequirements;
    IntegrityRequirement: SecurityRequirements;
    AvailabilityRequirement: SecurityRequirements;
}
