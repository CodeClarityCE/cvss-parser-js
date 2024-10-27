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
export var AccessVector;
(function (AccessVector) {
    AccessVector["NOT_DEFINED"] = "NOT_DEFINED";
    AccessVector["LOCAL"] = "LOCAL";
    AccessVector["ADJACENT_NETWORK"] = "ADJACENT_NETWORK";
    AccessVector["NETWORK"] = "NETWORK";
})(AccessVector || (AccessVector = {}));
/**
 * Access Complexity (AC)
 */
export var AccessComplexity;
(function (AccessComplexity) {
    AccessComplexity["NOT_DEFINED"] = "NOT_DEFINED";
    AccessComplexity["LOW"] = "LOW";
    AccessComplexity["MEDIUM"] = "MEDIUM";
    AccessComplexity["HIGH"] = "HIGH";
})(AccessComplexity || (AccessComplexity = {}));
/**
 * Authentication (Au)
 */
export var Authentication;
(function (Authentication) {
    Authentication["NOT_DEFINED"] = "NOT_DEFINED";
    Authentication["MULTIPLE"] = "MULTIPLE";
    Authentication["SINGLE"] = "SINGLE";
    Authentication["NONE"] = "NONE";
})(Authentication || (Authentication = {}));
/**
 * Impact (C, A, I)
 */
export var Impact;
(function (Impact) {
    Impact["NOT_DEFINED"] = "NOT_DEFINED";
    Impact["NONE"] = "NONE";
    Impact["PARTIAL"] = "PARTIAL";
    Impact["COMPLETE"] = "COMPLETE";
})(Impact || (Impact = {}));
/******************************************************************************/
/**                               Temporal Metrics                            */
/******************************************************************************/
/**
 * Exploitability (E)
 */
export var Exploitability;
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
    ReportConfidence["UNCONFIRMED"] = "UNCONFIRMED";
    ReportConfidence["UNCORROBORATED"] = "UNCORROBORATED";
    ReportConfidence["CONFIRMED"] = "CONFIRMED";
})(ReportConfidence || (ReportConfidence = {}));
/******************************************************************************/
/**                            Environmental Metrics                          */
/******************************************************************************/
/**
 * Collateral Damage Potential (CDP)
 */
export var CollateralDamagePotential;
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
export var TargetDistribution;
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
export var SecurityRequirements;
(function (SecurityRequirements) {
    SecurityRequirements["NOT_DEFINED"] = "NOT_DEFINED";
    SecurityRequirements["LOW"] = "LOW";
    SecurityRequirements["MEDIUM"] = "MEDIUM";
    SecurityRequirements["HIGH"] = "HIGH";
})(SecurityRequirements || (SecurityRequirements = {}));
