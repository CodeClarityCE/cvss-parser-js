/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v3.0/specification-document
 */
import { CVSS3Info } from '../../types/fields/cvss3.js';
export declare class CVSS3VectorParser {
    /**
     * Parse CVSS 3 Attack Vector
     */
    private parseAV;
    /**
     * Parse CVSS 3 Attack Complexity
     */
    private parseAC;
    /**
     * Parse CVSS 3 Privileges Required
     */
    private parsePR;
    /**
     * Parse CVSS 3 User Interaction
     */
    private parseUI;
    /**
     * Parse CVSS 3 Scope
     */
    private parseS;
    /**
     * Parse CVSS 3 Confidentiality, Availability, Integrity Impact
     */
    private parseImact;
    /**
     * Parse CVSS 3 Exploit Code Maturity
     */
    private parseE;
    /**
     * Parse CVSS 3 Exploit Code Maturity
     */
    private parseRL;
    /**
     * Parse CVSS 3 Report Confidence
     */
    private parseRC;
    /**
     * Parse CVSS 2 Security Requirements (CR, IR, AR)
     */
    private parseSecurityRequirement;
    /**
     * Parses a CVSS 3 vector
     * @param vector CVSS 3 vector String
     * @returns Parsed CVSS 3 Vector
     */
    parse(vector: string): CVSS3Info;
}
