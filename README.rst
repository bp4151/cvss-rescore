.. image:: https://img.shields.io/badge/-PyScaffold-005CA0?logo=pyscaffold
    :alt: Project generated with PyScaffold
    :target: https://pyscaffold.org/1

.. image:: https://bestpractices.coreinfrastructure.org/projects/6968/badge
    :alt: OpenSSF Badges
    :target: https://bestpractices.coreinfrastructure.org/projects/6968

============
cvss_rescore
============


    Rescore cvss3 and 3.1 results from any json file based on custom rules.

------------
The Problem
------------
Cvss scoring consists of three components: Base, Temporal, and Environmental.

When working with third-party dependency (SCA) vulnerabilities, 
nearly every tool reports it's scores only using the base score. This is
understandable, as the reporters of the vulnerabilities would only know about
the vulnerabilities themselves. They would have no idea how the vulnerable package
is actually used in your project. Do you have mitigating controls in place? Is it only
a test project? Is it only in a protected CI/CD pipeline? All of these factors and more
can impact the environmental score, which can lower the actual score of a vulnerability
significantly.

How We Use This
----------------

Output-Agnostic
================

We use the cvss-rescore packate as a post-processor after our SCA scan has been run. Because
the cvss-rescore package can take any json format output, it is tool-agnostic. We have tested 
it successfully using Dependabot and JFrog Xray, but there's no reason
any other tool can't be used so long as the output is json.

Rules-Based
============
Because we leverage the Python rule-engine package as a dependency, users can create a 
rules_actions.json file in their root directory. Users can create as many rules as they need, 
modifying one or more cvss vector metrics per rule. 

Requirements
=============
- Python 3.6 or higher
- A working knowledge of CVSS calcuation. You can reference the calculator at

| https://www.first.org/cvss/calculator/3.1     
| https://www.first.org/cvss/user-guide   
| https://www.first.org/cvss/v3.1/examples   

Documentation
==============
You can get the current documentation at https://cvss-rescore.readthedocs.io/en/latest/

.. _pyscaffold-notes:

Dependencies
=============
| rule-engine: https://pypi.org/project/rule-engine/
| cvss: https://pypi.org/project/cvss/


Note
====

This project has been set up using PyScaffold 4.3.1. For details and usage
information on PyScaffold see https://pyscaffold.org/.
