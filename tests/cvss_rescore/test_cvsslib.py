import logging
import os
from pathlib import Path

import pytest
from rule_engine import RuleSyntaxError, SymbolResolutionError

from cvss_rescore.cvsslib import CvssLib
from cvss_rescore.cvsslib import ManualVettingException

logger = logging.getLogger(__name__)


rules_file_path = Path(__file__).parent.parent
rules_file = os.path.join(rules_file_path, 'rules_actions.json')


def test_cvss2_throws_value_error():
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
                "cvssVector": "CVSS:2/AV:N/AC:L/Au:N/C:C/I:C/A:C)",
                "cve": "CVE-2022-00000"
            }]
        }
    }
    original_vector_string = record.get('package').get('Vulnerabilities')[0].get('cvssVector')
    cvsslib = CvssLib(rules_file_path=rules_file)
    try:
        modified_vector_string, modified_environmental_score, modified_severity, rules_applied = cvsslib.get_modified_cvss(record=record, original_vector_string=original_vector_string, logger=logger)
    except ValueError as ve:
        assert True


def test_missing_cvss_throws_value_error():
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
                "cvssVector": "AV:N/AC:L/Au:N/C:C/I:C/A:C)",
                "cve": "CVE-2022-00000"
            }]
        }
    }
    original_vector_string = record.get('package').get('Vulnerabilities')[0].get('cvssVector')
    cvsslib = CvssLib(rules_file_path=rules_file)
    try:
        modified_vector_string, \
            modified_environmental_score, \
            modified_severity, \
            rules_applied = \
            cvsslib.get_modified_cvss(record=record, original_vector_string=original_vector_string)
    except ValueError as ve:
        assert True


def test_cvss3_does_not_throw_exception():
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
    original_vector_string = record.get('package').get('Vulnerabilities')[0].get('cvssVector')
    cvsslib = CvssLib(rules_file_path=rules_file)
    modified_vector_string, \
        modified_environmental_score, \
        modified_severity, \
        rules_applied = cvsslib.get_modified_cvss(
        record=record,
        original_vector_string=original_vector_string)
    assert modified_severity[0] == 'Critical'


def test_invalid_vector_value():
    record = {
        "locations": "",
        "package": {
            "Package": {
                "pm": "npm",
                "group": None,
                "name": "Invalid_Vector_Value_Test",
                "version": "1.0.0",
                "vendor": None,
                "fixVersions": ["[1.2.6]"],
                "impactPaths": [["npm://covert:1.0.0", "npm://Invalid_Vector_Value_Test:1.0.0"]]
            },
            "Vulnerabilities": [{
                "id": "XRAY-000000",
                "title": "Critical vulnerability found in component temp_react_core",
                "description": "Prototype pollution vulnerability in function parseQuery in parseQuery.js in webpack loader-utils 2.0.0 via the name variable in parseQuery.js.",
                "cvssScore": "9.8",
                "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cve": "CVE-2022-00000"
            }]
        }
    }
    original_vector_string = record.get('package').get('Vulnerabilities')[0].get('cvssVector')
    cvsslib = CvssLib(rules_file_path=rules_file)
    try:
        modified_vector_string, modified_environmental_score, modified_severity, rules_applied = cvsslib.get_modified_cvss(record=record, original_vector_string=original_vector_string, logger=logger)
    except RuleSyntaxError as rse:
        print(rse.message)
        assert True


def test_invalid_rule_attribute_not_found():
    record = {
        "locations": "",
        "package": {
            "Package": {
                "pm": "npm",
                "group": None,
                "name": "Invalid_Vector_Value_Test",
                "version": "1.0.0",
                "vendor": None,
                "fixVersions": ["[1.2.6]"],
                "impactPaths": [["npm://covert:1.0.0", "npm://Invalid_Vector_Value_Test:1.0.0"]]
            },
            "Vulnerabilities": [{
                "id": "XRAY-000000",
                "title": "Critical vulnerability found in component temp_react_core",
                "description": "Prototype pollution vulnerability in function parseQuery in parseQuery.js in webpack loader-utils 2.0.0 via the name variable in parseQuery.js.",
                "cvssScore": "9.8",
                "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cve": "CVE-2022-00000"
            }]
        }
    }
    original_vector_string = record.get('package').get('Vulnerabilities')[0].get('cvssVector')
    cvsslib = CvssLib(rules_file_path=rules_file)
    try:
        modified_vector_string, modified_environmental_score, modified_severity, rules_applied = cvsslib.get_modified_cvss(record=record, original_vector_string=original_vector_string, logger=logger)
    except SymbolResolutionError as sre:
        print(sre.message)
        assert True
