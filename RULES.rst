=====
Rules
=====

Rules are based on the Python package rule-engine (rule-engine: https://pypi.org/project/rule-engine/)

A properly formatted rule file should be an array of dictionary objects

The following is an example rule block dictionary:::

    {
        "description": "CVE exists, set RC=C",
        "rule": "package.Vulnerabilities[0]['cve']",
        "vector_changes": [
            {
                "vector": "RC",
                "value": "C"
            }
        ]
    }


In the above case,

- description: any string
- rule: string indicating the path to the data in your source file that you want to test
- vector_changes: array of name/value pairs. These are the vector metrics that will be used to create the modified vector string that will be used to rescore the vulnerability

| For documentation regarding rule-engine usage, refer to https://zerosteiner.github.io/rule-engine/index.html
| For a specific use case regarding creating rules using list comprehensions, see https://github.com/zeroSteiner/rule-engine/issues/38#issuecomment-1117437907
