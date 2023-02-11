=====
Rules
=====

Rules are based on the Python package rule-engine (rule-engine: https://pypi.org/project/rule-engine/)

In order to use the cvss-rescore package, you will need to create a rule file. A properly formatted rule file should be an array of dictionary objects

The following is an example rule block dictionary:::

    [
        {
            "description": "CVE exists, set RC=C",
            "rule": "package.Vulnerabilities[0]['cve']",
            "vector_changes": [
                {
                    "vector": "RC",
                    "value": "C"
                }
            ]
        },
        {
            "description": "A fix version exists, so set the fix version vector",
            "rule": "package.Package.fixVersions",
            "vector_changes": [
                {
                    "vector": "RL",
                    "value": "O"
                }
            ]
        },
    ]


In the above case,

- description: any string
- rule: string indicating the path to the data in your source file that you want to test
- vector_changes: array of name/value pairs. These are the vector metrics that will be used to create the modified vector string that will be used to rescore the vulnerability.

| In the first rule example above, if a cve is defined in

::

    {
        'package': {
            'Vulnerabilities: [{
                'cve': 'CVE-2021-3749'
            }]
        }
    }

then set the RC, or Report Confidence vector portion of the Cvss vector string and rescore the vulnerability.

| In the second rule example above, if a fix version exists in

::

    {
        'package': {
            'Package: {
                'fixVersions': ["[1.2.6]"],
            }
        }
    }

then set the RL, or Remediation Level vector portion of the Cvss vector string and rescore the vulnerability.

| vector and value are defined as part of the CVSS3.x calculator. For full details and examples regarding the Cvss Calculator, see the following links.
| https://www.first.org/cvss/v3.1/specification-document
|

| For documentation regarding rule-engine usage, refer to https://zerosteiner.github.io/rule-engine/index.html
| For a specific use case regarding creating rules using list comprehensions, see https://github.com/zeroSteiner/rule-engine/issues/38#issuecomment-1117437907
