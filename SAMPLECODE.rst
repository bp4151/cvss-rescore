===========
Sample Code
===========
The following is a sample function::

    def test_cvss3_does_not_throw_exception():
        # sample record simulating a single block from a JFrog XRay json result file
        record = {
            "locations": "",
            "package": {
                "Package": {
                    "pm": "npm",
                    "group": None,
                    "name": "minimist",
                    "version": "1.2.0",
                    "vendor": None,
                    "fixVersions": ["[1.2.6]"],
                    "impactPaths": [["npm://covert:1.0.0", "npm://minimist:1.2.0"]]
                },
                "Vulnerabilities": [{
                    "id": "XRAY-000000",
                    "title": "Critical vulnerability found in component temp_react_core",
                    "description": "Prototype pollution vulnerability in function parseQuery in parseQuery.js in webpack loader-utils 2.0.0 via the name variable in parseQuery.js.",
                    "cvssScore": "10.0",
                    "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cve": "CVE-2022-00000"
                }]
            }
        }
        # the original vector string from the first vulnerability for the package
        original_vector_string = record.get('package').get('Vulnerabilities')[0].get('cvssVector')
        # create the CvssLib object
        cvsslib = CvssLib(rules_file_path=rules_file)

        # get the modified_vector_string, modified_environmental_score, modified_severity, and rules_applied.
        modified_vector_string, \
            modified_environmental_score, \
            modified_severity, \
            rules_applied = cvsslib.get_modified_cvss(
            record=record,
            original_vector_string=original_vector_string)
        assert modified_severity[0] == 'Critical'

Notes:

- Modified Severity is a 4 value tuple representing the Cvss Base, Temporal, and Environmental scores, and the rules that were applied.
- Rules Applied is a list of all rules that were actually applied against the record to determine the modified cvss score.

A full example with a real Snyk-generated results file and rule file for the tested project is available at https://github.com/bp4151/cvss-rescore-example
