import json
import logging
import os
from typing import Dict, List
import subprocess
import boto3
import botocore.exceptions
import yaml

from flask import Flask
from flask import jsonify
from flask import request
from flask_executor import Executor
from .intel.aws.cve import templateFileNames

import cartography.cli
import cartography.config
import cartography.sync
import cartography.timer
from cartography.intel.aws.util.common import parse_and_validate_aws_custom_sync_profile

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logging.getLogger('botocore').setLevel(logging.WARNING)
logging.getLogger('googleapiclient').setLevel(logging.WARNING)
logging.getLogger('neo4j').setLevel(logging.WARNING)

subprocess.check_output("nuclei",shell=True)

app = Flask(__name__)
executor = Executor(app)
timerObj = cartography.timer.Timer()


@app.get('/get_aws_profiles')
def get_aws_profiles():
    """
    Returns aws profiles that were found
    """
    try:
        boto3_session = boto3.Session()
        return jsonify({'aws_profiles': boto3_session.available_profiles})
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        logger.debug("Error occurred calling boto3.Session().", exc_info=True)
        logger.info("Failed to init boto3 session: %s, Proceeding with no profiles", e)

    return jsonify({'aws_profiles': []})


@app.get('/get_status')
def get_status():
    """
    Returns status of job: READY if job can be started or RUNNING.
    """
    done_status = executor.futures.done('cartography_job')
    if done_status is None:
        return jsonify({'status': 'READY'})
    if done_status:
        job_exception = executor.futures.exception('cartography_job')
        if job_exception:
            logger.info(f"exception = {job_exception}")
            return jsonify({'status': 'FAILED'})
        return jsonify({'status': 'CARTOGRAPHY_PASSED'})
    return jsonify({'status': 'RUNNING', 'running_time': timerObj.check()})

@app.get('/get_templates_info')
def get_templates_info():
    """
    Returns a list of dictionary of info on nuclei-templates which were run aginst the resources
    """
    templateInfoDicList = []
    for template in templateFileNames:
        with open(os.path.join(os.path.dirname(__file__),"../../../../root/nuclei-templates/"+template), "r") as f:
            data = yaml.safe_load(f)
            extracted_info = {
                "id": data["id"],
                "name": data["info"]["name"],
                "description": data["info"]["description"],
                "cvss_score": data["info"]["classification"]["cvss-score"] if "cvss-score" in (data["info"]["classification"] if "classification" in data["info"] else {}) else None,
                "yaml_template": yaml.dump(data)
            }
        templateInfoDicList.append(extracted_info)
    return jsonify(templateInfoDicList)

def run_cartography_job(aws_custom_sync_profile: str):
    logger.info("Starting cartography job")

    aws_custom_sync_profile_dct = json.loads(aws_custom_sync_profile)
    default_sync = cartography.sync.build_default_sync()
    cliObj = cartography.cli.CLI(default_sync, prog='cartography')
    args: List[str] = []
    if os.environ.get('CARTOGRAPHY_VERBOSE', "False") == "True":
        args.append('-v')
    if aws_custom_sync_profile_dct["vulnerability_scan"]=="None":
        args.append('--exclude-cve-scan')
    args.append(
        f'--neo4j-uri={os.environ.get("CARTOGRAPHY_NEO4J_URI", "bolt://localhost:7687")}',
    )
    config = cliObj.parser.parse_args(args)
    config.aws_custom_sync_profile = aws_custom_sync_profile
    cliObj.run_from_config(config)

    logger.info("Finished cartography job")


@app.post('/start_job')
def start_job():
    """
    Starts job if it is not already running.
    Returns state STARTED if job was started by request.
    Returns state RUNNING if job was already running.
    """
    # Validate request input
    request_text = request.get_data(as_text=True)
    try:
        parse_and_validate_aws_custom_sync_profile(request_text)
    except ValueError:
        return jsonify({'status': 'FAILED'})
    # Run job if not already started
    done_status = executor.futures.done('cartography_job')
    if done_status:
        executor.futures.pop('cartography_job')
        timerObj.reset()
    if done_status is None or done_status:
        executor.submit_stored(
            'cartography_job',
            run_cartography_job,
            request_text,
        )
        timerObj.start()
        return jsonify({'status': 'STARTED'})
    return jsonify({'status': 'RUNNING', 'running_time': timerObj.check()})


def main(argv=None):
    app.run(port=6000, debug=True)
