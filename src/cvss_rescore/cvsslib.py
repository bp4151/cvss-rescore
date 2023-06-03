import json
import logging

from cvss.cvss3 import CVSS3
from rule_engine import Rule, SymbolResolutionError, RuleSyntaxError
from .manualVettingException import ManualVettingException


class CvssLib:

    rules_actions = None
    logger = logging.getLogger()

    @classmethod
    def __init__(cls, rules_file_path: str):
        """
        :param rules_file_path: str
        :rtype: object
        """
        cls.rules_actions = cls.__get_rules_actions(
            rules_file_path=rules_file_path)

    @classmethod
    def get_modified_cvss(cls,
                          record: dict,
                          original_vector_string: str) -> tuple:
        """
        :param record: dict - This is a single vulnerability record from your json output file
        :param original_vector_string: str
        :return:
        :rtype: tuple - modified_vector_string, modified_environmental_score, \
            modified_severity, rules_applied
        :exception: SymbolResolutionError will log to error if the path in your
            custom rule cannot be found in the source json file
        :exception: RuleSyntaxError will log to error if the rule you have
            defined cannot be parsed.
        :exception: ManualVettingException will be thrown if no rules were matched.
            This can be caught in your parent script
        """
        # convert the original vector string to a dict
        original_vector_obj = cls.__str2dict(original_vector_string)
        # check if the vector string contains `CVSS`
        if original_vector_obj.get('CVSS') is None:
            raise ValueError('CVSS vector string does not contain CVSS, manual vetting required')
        else:
            # if we have a CVSS object and the value is 3.x, use the CVSS3 class
            # if we have a CVSS object and the value is 2.x, raise an error
            if original_vector_obj['CVSS'].startswith('3'):
                cvss_obj = CVSS3(original_vector_string)
            elif original_vector_obj['CVSS'].startswith('2'):
                raise ValueError(f'CVSS version {original_vector_obj["CVSS"]} is unsupported, manual vetting required')
        results = []
        rules_applied = []
        result = False
        for rule_action in cls.rules_actions:
            try:
                rule = Rule(rule_action['rule'])
                result = rule.matches(record)
            except SymbolResolutionError as srerr:
                cls.logger.error(f'{srerr.message}. The {srerr.symbol_name} block in the rules_actions.json file '
                                 f'was not found in the json record')
            # if true, we need to update the vector string and return it.
            except RuleSyntaxError as rserr:
                cls.logger.error(f'{rserr.message}. The block value in the '
                                 f'rules_actions.json file '
                                 f'contains incorrect syntax.')
            if result is True:
                rules_applied.append({
                    "description": rule_action['description'],
                    "vector_changes": rule_action["vector_changes"]
                })
                for vector_change in rule_action["vector_changes"]:
                    cvss_obj.metrics[vector_change['vector']] = vector_change['value']
                cvss_obj.compute_temporal_score()
                cvss_obj.compute_environmental_score()
            results.append(result)

        if True not in results:
            raise ManualVettingException("No rescore rules were matched by this record. Manual vetting is required!")

        modified_vector_string = f'CVSS:3.{cvss_obj.minor_version}/{cls.__dict2str(cvss_obj.metrics)}'
        modified_environmental_score = cvss_obj.environmental_score
        modified_severity = cvss_obj.severities()
        return modified_vector_string, modified_environmental_score, \
            modified_severity, rules_applied

    @classmethod
    def __str2dict(cls, vector_string: str) -> dict:
        vector_dict = {}
        vector_parts = vector_string.split('/')
        for vector_part in vector_parts:
            key = vector_part.split(':')[0]
            value = vector_part.split(':')[1]
            vector_dict[key] = value

        return vector_dict

    @classmethod
    def __dict2str(cls, vector_object: dict) -> str:
        vector_string = ''
        for key in vector_object.keys():
            value = vector_object[key]
            vector_part = f'{key}:{value}'
            vector_string = f'{vector_string}/{vector_part}'

        # remove leading /
        vector_string = vector_string.lstrip('/')
        return vector_string

    @classmethod
    def __get_rules_actions(cls, rules_file_path: str) -> dict:
        with open(rules_file_path, 'r') as r:
            rules_actions = json.load(r)
        return rules_actions
