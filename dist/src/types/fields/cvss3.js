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
export var AttackVector;
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
export var AttackComplexity;
(function (AttackComplexity) {
    AttackComplexity["NOT_DEFINED"] = "NOT_DEFINED";
    AttackComplexity["LOW"] = "LOW";
    AttackComplexity["HIGH"] = "HIGH";
})(AttackComplexity || (AttackComplexity = {}));
/**
 * Privileges Required (PR)
 */
export var PrivilegesRequired;
(function (PrivilegesRequired) {
    PrivilegesRequired["NOT_DEFINED"] = "NOT_DEFINED";
    PrivilegesRequired["HIGH"] = "HIGH";
    PrivilegesRequired["LOW"] = "LOW";
    PrivilegesRequired["NONE"] = "NONE";
})(PrivilegesRequired || (PrivilegesRequired = {}));
/**
 * User Interaction (UI)
 */
export var UserInteraction;
(function (UserInteraction) {
    UserInteraction["NOT_DEFINED"] = "NOT_DEFINED";
    UserInteraction["REQUIRED"] = "REQUIRED";
    UserInteraction["NONE"] = "NONE";
})(UserInteraction || (UserInteraction = {}));
/**
 * Scope (S)
 */
export var Scope;
(function (Scope) {
    Scope["NOT_DEFINED"] = "NOT_DEFINED";
    Scope["UNCHANGED"] = "UNCHANGED";
    Scope["CHANGED"] = "CHANGED";
})(Scope || (Scope = {}));
/**
 * Impact (C, A, I)
 */
export var Impact;
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
export var ExploitCodeMaturity;
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
export var RemediationLevel;
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
export var ReportConfidence;
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
export var SecurityRequirements;
(function (SecurityRequirements) {
    SecurityRequirements["NOT_DEFINED"] = "NOT_DEFINED";
    SecurityRequirements["LOW"] = "LOW";
    SecurityRequirements["MEDIUM"] = "MEDIUM";
    SecurityRequirements["HIGH"] = "HIGH";
})(SecurityRequirements || (SecurityRequirements = {}));
