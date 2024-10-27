/**
 * @author Ohlhoff Claude
 * Spec: https://www.first.org/cvss/v2/guide
 */
import { CVSS2Info } from '../../types/fields/cvss2.js';
export declare class CVSS2VectorParser {
    /**
     * Parse CVSS 2 Access Vector
     */
    private parseAV;
    /**
     * Parse CVSS 2 Access Complexity
     */
    private parseAC;
    /**
     * Parse CVSS 2 Authentication
     */
    private parseAu;
    /**
     * Parse CVSS 2 Confidentiality, Availability, Integrity Impact
     */
    private parseImact;
    /**
     * Parse CVSS 2 Exploitability
     */
    private parseE;
    /**
     * Parse CVSS 2 Remediation Level
     */
    private parseRL;
    /**
     * Parse CVSS 2 Report Confidence
     */
    private parseRC;
    /**
     * Parse CVSS 2 Colleteral Damange Potential
     */
    private parseCDP;
    /**
     * Parse CVSS 2 Target Distribution
     */
    private parseTD;
    /**
     * Parse CVSS 2 Security Requirements (CR, IR, AR)
     */
    private parseSecurityRequirement;
    /**
     * Parses a CVSS 2 vector
     * @param vector CVSS 2 vector String
     * @returns Parsed CVSS 2 Vector
     */
    parse(vector: string): CVSS2Info;
}
