/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v3.1/specification-document
 */
import { CVSS31Info } from '../../types/fields/cvss31.js';
export declare class CVSS31VectorParser {
    /**
     * Parse CVSS 3.1 Attack Vector
     */
    private parseAV;
    /**
     * Parse CVSS 3.1 Attack Complexity
     */
    private parseAC;
    /**
     * Parse CVSS 3.1 Privileges Required
     */
    private parsePR;
    /**
     * Parse CVSS 3.1 User Interaction
     */
    private parseUI;
    /**
     * Parse CVSS 3.1 Scope
     */
    private parseS;
    /**
     * Parse CVSS 3.1 Confidentiality, Availability, Integrity Impact
     */
    private parseImact;
    /**
     * Parse CVSS 3.1 Exploit Code Maturity
     */
    private parseE;
    /**
     * Parse CVSS 3.1 Exploit Code Maturity
     */
    private parseRL;
    /**
     * Parse CVSS 3.1 Report Confidence
     */
    private parseRC;
    /**
     * Parse CVSS 2 Security Requirements (CR, IR, AR)
     */
    private parseSecurityRequirement;
    /**
     * Parses a CVSS 3.1 vector
     * @param vector CVSS 3.1 vector String
     * @returns Parsed CVSS 3.1 Vector
     */
    parse(vector: string): CVSS31Info;
}
