import { CVSS2Calculator } from './src/calculators/cvss2/calc.js';
import { CVSS3Calculator } from './src/calculators/cvss3/calc.js';
import { CVSS31Calculator } from './src/calculators/cvss31/calc.js';
import { CVSS2VectorParser } from './src/parsers/cvss2/parser.js';
import { CVSS3VectorParser } from './src/parsers/cvss3/parser.js';
import { CVSS31VectorParser } from './src/parsers/cvss31/parser.js';
export function createCVSS2Parser() {
    return new CVSS2VectorParser();
}
export function createCVSS3Parser() {
    return new CVSS3VectorParser();
}
export function createCVSS31Parser() {
    return new CVSS31VectorParser();
}
export function createCVSS2Calculator() {
    return new CVSS2Calculator();
}
export function createCVSS3Calculator() {
    return new CVSS3Calculator();
}
export function createCVSS31Calculator() {
    return new CVSS31Calculator();
}
