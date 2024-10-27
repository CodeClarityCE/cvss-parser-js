/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v4.0/specification-document
 */
/******************************************************************************/
/**                                 Base Metrics                              */
/******************************************************************************/
/**
 * Attack Vector (AV)
 */
export declare enum AttackVector {
    NOT_DEFINED = 0,
    PHYSICAL = 1,
    LOCAL = 2,
    ADJACENT_NETWORK = 3,
    NETWORK = 4
}
/**
 * Attack Complexity (AC)
 */
export declare enum AttackComplexity {
    NOT_DEFINED = 0,
    LOW = 1,
    HIGH = 2
}
/**
 * Attack Requirements (AT)
 */
export declare enum AttackRequirements {
    NOT_DEFINED = 0,
    NONE = 1,
    PRESENT = 2
}
/**
 * Privileges Required (PR)
 */
export declare enum PrivilegesRequired {
    NOT_DEFINED = 0,
    HIGH = 1,
    LOW = 2,
    NONE = 3
}
/**
 * User Interaction (UI)
 */
export declare enum UserInteraction {
    NOT_DEFINED = 0,
    ACTIVE = 1,
    PASSIVE = 2,
    NONE = 3
}
/**
 * Scope (S)
 */
export declare enum Scope {
    NOT_DEFINED = 0,
    UNCHANGED = 1,
    CHANGED = 2
}
/**
 * Confidentiality Impact to the Vulnerable System (VC)
 */
export declare enum ConfidentialityImpactToVulnerableSystem {
    NOT_DEFINED = 0,
    NONE = 1,
    LOW = 2,
    HIGH = 3
}
/**
 * Confidentiality Impact to the Subsequent System (SC)
 */
export declare enum ConfidentialityImpactToSubsequentSystem {
    NOT_DEFINED = 0,
    NEGLIGBILE = 1,
    LOW = 2,
    HIGH = 3
}
/**
 * Integrity Impact to the Vulnerable System (VI)
 */
export declare enum IntegrityImpactToVulnerableSystem {
    NOT_DEFINED = 0,
    NONE = 1,
    LOW = 2,
    HIGH = 3
}
/**
 * Integrity Impact to the Subsequent System (SI)
 */
export declare enum IntegrityImpactToSubsequentSystem {
    NOT_DEFINED = 0,
    NEGLIGBILE = 1,
    LOW = 2,
    HIGH = 3
}
/**
 * Availability Impact To Vulnerable System (VA)
 */
export declare enum AvailabilityImpactToVulnerableSystem {
    NOT_DEFINED = 0,
    NONE = 1,
    LOW = 2,
    HIGH = 3
}
/**
 * Availability Impact To Subsequent System (SA)
 */
export declare enum AvailabilityImpactToSubsequentSystem {
    NOT_DEFINED = 0,
    NEGLIGBILE = 1,
    LOW = 2,
    HIGH = 3
}
/******************************************************************************/
/**                                Threat Metrics                             */
/******************************************************************************/
/**
 * Exploit Maturity (E)
 */
export declare enum ExploitMaturity {
    NOT_DEFINED = 0,
    UNREPORTED = 1,
    PROOF_OF_CONCEPT = 2,
    ATTACKED = 3
}
/******************************************************************************/
/**                            Environmental Metrics                          */
/******************************************************************************/
/**
 * Security Requirements (CR, IR, AR)
 */
export declare enum SecurityRequirements {
    NOT_DEFINED = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3
}
