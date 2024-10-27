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
export var AttackVector;
(function (AttackVector) {
    AttackVector[AttackVector["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    AttackVector[AttackVector["PHYSICAL"] = 1] = "PHYSICAL";
    AttackVector[AttackVector["LOCAL"] = 2] = "LOCAL";
    AttackVector[AttackVector["ADJACENT_NETWORK"] = 3] = "ADJACENT_NETWORK";
    AttackVector[AttackVector["NETWORK"] = 4] = "NETWORK";
})(AttackVector || (AttackVector = {}));
/**
 * Attack Complexity (AC)
 */
export var AttackComplexity;
(function (AttackComplexity) {
    AttackComplexity[AttackComplexity["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    AttackComplexity[AttackComplexity["LOW"] = 1] = "LOW";
    AttackComplexity[AttackComplexity["HIGH"] = 2] = "HIGH";
})(AttackComplexity || (AttackComplexity = {}));
/**
 * Attack Requirements (AT)
 */
export var AttackRequirements;
(function (AttackRequirements) {
    AttackRequirements[AttackRequirements["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    AttackRequirements[AttackRequirements["NONE"] = 1] = "NONE";
    AttackRequirements[AttackRequirements["PRESENT"] = 2] = "PRESENT";
})(AttackRequirements || (AttackRequirements = {}));
/**
 * Privileges Required (PR)
 */
export var PrivilegesRequired;
(function (PrivilegesRequired) {
    PrivilegesRequired[PrivilegesRequired["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    PrivilegesRequired[PrivilegesRequired["HIGH"] = 1] = "HIGH";
    PrivilegesRequired[PrivilegesRequired["LOW"] = 2] = "LOW";
    PrivilegesRequired[PrivilegesRequired["NONE"] = 3] = "NONE";
})(PrivilegesRequired || (PrivilegesRequired = {}));
/**
 * User Interaction (UI)
 */
export var UserInteraction;
(function (UserInteraction) {
    UserInteraction[UserInteraction["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    UserInteraction[UserInteraction["ACTIVE"] = 1] = "ACTIVE";
    UserInteraction[UserInteraction["PASSIVE"] = 2] = "PASSIVE";
    UserInteraction[UserInteraction["NONE"] = 3] = "NONE";
})(UserInteraction || (UserInteraction = {}));
/**
 * Scope (S)
 */
export var Scope;
(function (Scope) {
    Scope[Scope["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    Scope[Scope["UNCHANGED"] = 1] = "UNCHANGED";
    Scope[Scope["CHANGED"] = 2] = "CHANGED";
})(Scope || (Scope = {}));
/**
 * Confidentiality Impact to the Vulnerable System (VC)
 */
export var ConfidentialityImpactToVulnerableSystem;
(function (ConfidentialityImpactToVulnerableSystem) {
    ConfidentialityImpactToVulnerableSystem[ConfidentialityImpactToVulnerableSystem["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    ConfidentialityImpactToVulnerableSystem[ConfidentialityImpactToVulnerableSystem["NONE"] = 1] = "NONE";
    ConfidentialityImpactToVulnerableSystem[ConfidentialityImpactToVulnerableSystem["LOW"] = 2] = "LOW";
    ConfidentialityImpactToVulnerableSystem[ConfidentialityImpactToVulnerableSystem["HIGH"] = 3] = "HIGH";
})(ConfidentialityImpactToVulnerableSystem || (ConfidentialityImpactToVulnerableSystem = {}));
/**
 * Confidentiality Impact to the Subsequent System (SC)
 */
export var ConfidentialityImpactToSubsequentSystem;
(function (ConfidentialityImpactToSubsequentSystem) {
    ConfidentialityImpactToSubsequentSystem[ConfidentialityImpactToSubsequentSystem["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    ConfidentialityImpactToSubsequentSystem[ConfidentialityImpactToSubsequentSystem["NEGLIGBILE"] = 1] = "NEGLIGBILE";
    ConfidentialityImpactToSubsequentSystem[ConfidentialityImpactToSubsequentSystem["LOW"] = 2] = "LOW";
    ConfidentialityImpactToSubsequentSystem[ConfidentialityImpactToSubsequentSystem["HIGH"] = 3] = "HIGH";
})(ConfidentialityImpactToSubsequentSystem || (ConfidentialityImpactToSubsequentSystem = {}));
/**
 * Integrity Impact to the Vulnerable System (VI)
 */
export var IntegrityImpactToVulnerableSystem;
(function (IntegrityImpactToVulnerableSystem) {
    IntegrityImpactToVulnerableSystem[IntegrityImpactToVulnerableSystem["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    IntegrityImpactToVulnerableSystem[IntegrityImpactToVulnerableSystem["NONE"] = 1] = "NONE";
    IntegrityImpactToVulnerableSystem[IntegrityImpactToVulnerableSystem["LOW"] = 2] = "LOW";
    IntegrityImpactToVulnerableSystem[IntegrityImpactToVulnerableSystem["HIGH"] = 3] = "HIGH";
})(IntegrityImpactToVulnerableSystem || (IntegrityImpactToVulnerableSystem = {}));
/**
 * Integrity Impact to the Subsequent System (SI)
 */
export var IntegrityImpactToSubsequentSystem;
(function (IntegrityImpactToSubsequentSystem) {
    IntegrityImpactToSubsequentSystem[IntegrityImpactToSubsequentSystem["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    IntegrityImpactToSubsequentSystem[IntegrityImpactToSubsequentSystem["NEGLIGBILE"] = 1] = "NEGLIGBILE";
    IntegrityImpactToSubsequentSystem[IntegrityImpactToSubsequentSystem["LOW"] = 2] = "LOW";
    IntegrityImpactToSubsequentSystem[IntegrityImpactToSubsequentSystem["HIGH"] = 3] = "HIGH";
})(IntegrityImpactToSubsequentSystem || (IntegrityImpactToSubsequentSystem = {}));
/**
 * Availability Impact To Vulnerable System (VA)
 */
export var AvailabilityImpactToVulnerableSystem;
(function (AvailabilityImpactToVulnerableSystem) {
    AvailabilityImpactToVulnerableSystem[AvailabilityImpactToVulnerableSystem["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    AvailabilityImpactToVulnerableSystem[AvailabilityImpactToVulnerableSystem["NONE"] = 1] = "NONE";
    AvailabilityImpactToVulnerableSystem[AvailabilityImpactToVulnerableSystem["LOW"] = 2] = "LOW";
    AvailabilityImpactToVulnerableSystem[AvailabilityImpactToVulnerableSystem["HIGH"] = 3] = "HIGH";
})(AvailabilityImpactToVulnerableSystem || (AvailabilityImpactToVulnerableSystem = {}));
/**
 * Availability Impact To Subsequent System (SA)
 */
export var AvailabilityImpactToSubsequentSystem;
(function (AvailabilityImpactToSubsequentSystem) {
    AvailabilityImpactToSubsequentSystem[AvailabilityImpactToSubsequentSystem["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    AvailabilityImpactToSubsequentSystem[AvailabilityImpactToSubsequentSystem["NEGLIGBILE"] = 1] = "NEGLIGBILE";
    AvailabilityImpactToSubsequentSystem[AvailabilityImpactToSubsequentSystem["LOW"] = 2] = "LOW";
    AvailabilityImpactToSubsequentSystem[AvailabilityImpactToSubsequentSystem["HIGH"] = 3] = "HIGH";
})(AvailabilityImpactToSubsequentSystem || (AvailabilityImpactToSubsequentSystem = {}));
/******************************************************************************/
/**                                Threat Metrics                             */
/******************************************************************************/
/**
 * Exploit Maturity (E)
 */
export var ExploitMaturity;
(function (ExploitMaturity) {
    ExploitMaturity[ExploitMaturity["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    ExploitMaturity[ExploitMaturity["UNREPORTED"] = 1] = "UNREPORTED";
    ExploitMaturity[ExploitMaturity["PROOF_OF_CONCEPT"] = 2] = "PROOF_OF_CONCEPT";
    ExploitMaturity[ExploitMaturity["ATTACKED"] = 3] = "ATTACKED";
})(ExploitMaturity || (ExploitMaturity = {}));
/******************************************************************************/
/**                            Environmental Metrics                          */
/******************************************************************************/
/**
 * Security Requirements (CR, IR, AR)
 */
export var SecurityRequirements;
(function (SecurityRequirements) {
    SecurityRequirements[SecurityRequirements["NOT_DEFINED"] = 0] = "NOT_DEFINED";
    SecurityRequirements[SecurityRequirements["LOW"] = 1] = "LOW";
    SecurityRequirements[SecurityRequirements["MEDIUM"] = 2] = "MEDIUM";
    SecurityRequirements[SecurityRequirements["HIGH"] = 3] = "HIGH";
})(SecurityRequirements || (SecurityRequirements = {}));
