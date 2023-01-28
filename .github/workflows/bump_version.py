import logging
import os
import sys

import requests as requests
import semver
from dotenv import load_dotenv
from requests import Response

FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
formatter = logging.Formatter(FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(stream=sys.stdout)
ch.setFormatter(formatter)
logger.addHandler(ch)


def get_github_latest_release(token: str, owner: str, repo: str) -> Response:
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28',
    }

    response = requests.get(
        url=f'https://api.github.com/repos/{owner}/{repo}/releases/latest',
        headers=headers)
    return response


def create_github_release(
        token: str,
        owner: str,
        repo: str,
        tag: str,
        generate_release_notes: bool):
    generate_release_notes = str(generate_release_notes).lower()
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': f'Bearer {token}',
        'X-GitHub-Api-Version': '2022-11-28',
    }

    data = '{' \
           f'"tag_name":"{tag}",' \
           '"target_commitish":"main",' \
           f'"name":"{tag}",' \
           '"body":"",' \
           '"draft":false,' \
           '"prerelease":false,' \
           f'"generate_release_notes":{generate_release_notes}'

    response = requests.post(url=f'https://api.github.com/repos/{owner}/{repo}/releases',
                             headers=headers,
                             data=data)
    print(response.text)


def main(token: str, owner: str, repo: str):

    release = get_github_latest_release(token=token, owner=owner, repo=repo)

    data = release.json()
    if data.get('message', '') == '':
        # message only exists if no releases exist
        # we have a release, get the current release number and
        # strip the v prefix
        current_release_tag = data.get('tag_name').replace('v', '')
        logger.info(f'Releases exist. Current release is {current_release_tag}')

        new_release_tag = f'v{semver.bump_patch(version=current_release_tag)}'
        logger.info(f'New release created: {new_release_tag}')
        create_github_release(
            token=token,
            owner=owner,
            repo=repo,
            tag=new_release_tag,
            generate_release_notes=True)

    else:
        # message property exists and has a value
        # create a new release so we can start
        logger.info('No releases exist. Setting original tag to v0.0.1')
        current_release_tag = 'v0.0.1'
        create_github_release(
            token=token,
            owner=owner,
            repo=repo,
            tag=current_release_tag,
            generate_release_notes=False)


if __name__ == '__main__':
    load_dotenv()
    cvss_rescore_gh_token = os.getenv('CVSS_RESCORE_GH_TOKEN')
    owner = os.getenv('OWNER')
    repo = os.getenv('REPO')

    main(token=cvss_rescore_gh_token, owner=owner, repo=repo)
