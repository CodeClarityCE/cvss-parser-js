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
export enum AttackVector {
    NOT_DEFINED,
    PHYSICAL,
    LOCAL,
    ADJACENT_NETWORK,
    NETWORK
}

/**
 * Attack Complexity (AC)
 */
export enum AttackComplexity {
    NOT_DEFINED,
    LOW,
    HIGH
}

/**
 * Attack Requirements (AT)
 */
export enum AttackRequirements {
    NOT_DEFINED,
    NONE,
    PRESENT
}

/**
 * Privileges Required (PR)
 */
export enum PrivilegesRequired {
    NOT_DEFINED,
    HIGH,
    LOW,
    NONE
}

/**
 * User Interaction (UI)
 */
export enum UserInteraction {
    NOT_DEFINED,
    ACTIVE,
    PASSIVE,
    NONE
}

/**
 * Scope (S)
 */
export enum Scope {
    NOT_DEFINED,
    UNCHANGED,
    CHANGED
}

/**
 * Confidentiality Impact to the Vulnerable System (VC)
 */
export enum ConfidentialityImpactToVulnerableSystem {
    NOT_DEFINED,
    NONE,
    LOW,
    HIGH
}

/**
 * Confidentiality Impact to the Subsequent System (SC)
 */
export enum ConfidentialityImpactToSubsequentSystem {
    NOT_DEFINED,
    NEGLIGBILE,
    LOW,
    HIGH
}

/**
 * Integrity Impact to the Vulnerable System (VI)
 */
export enum IntegrityImpactToVulnerableSystem {
    NOT_DEFINED,
    NONE,
    LOW,
    HIGH
}

/**
 * Integrity Impact to the Subsequent System (SI)
 */
export enum IntegrityImpactToSubsequentSystem {
    NOT_DEFINED,
    NEGLIGBILE,
    LOW,
    HIGH
}

/**
 * Availability Impact To Vulnerable System (VA)
 */
export enum AvailabilityImpactToVulnerableSystem {
    NOT_DEFINED,
    NONE,
    LOW,
    HIGH
}

/**
 * Availability Impact To Subsequent System (SA)
 */
export enum AvailabilityImpactToSubsequentSystem {
    NOT_DEFINED,
    NEGLIGBILE,
    LOW,
    HIGH
}

/******************************************************************************/
/**                                Threat Metrics                             */
/******************************************************************************/

/**
 * Exploit Maturity (E)
 */
export enum ExploitMaturity {
    NOT_DEFINED,
    UNREPORTED,
    PROOF_OF_CONCEPT,
    ATTACKED
}

/******************************************************************************/
/**                            Environmental Metrics                          */
/******************************************************************************/

/**
 * Security Requirements (CR, IR, AR)
 */
export enum SecurityRequirements {
    NOT_DEFINED,
    LOW,
    MEDIUM,
    HIGH
}
