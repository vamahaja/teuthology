import os
import logging
import shlex
import sys
import datetime

from docopt import docopt
from typing import Dict, List, Optional, Union

from unittest.mock import patch

from teuthology import suite, schedule, parallel, run
from teuthology.misc import get_user,
from scripts.schedule import doc as schedule_doc
from .provisioner import Provisioner
import yaml

log = logging.getLogger(__name__)
job_id, job_configs = 1, []


def override_arg_defaults(name: str, default: str, env: str = os.environ):
    """Override default variable arguments from environment variables.

    :param name: The override veriable name.
    :param default: The defaule value to return if variable is absent.
    :param env: The environment variable.
    """
    env_arg = {
        "--ceph-repo": "TEUTH_CEPH_REPO",
        "--suite-repo": "TEUTH_SUITE_REPO",
        "--ceph-branch": "TEUTH_CEPH_BRANCH",
        "--suite-branch": "TEUTH_SUITE_BRANCH",
    }
    if name in env_arg and env_arg[name] in env.keys():
        variable = env_arg[name]
        value = env[variable]
        log.debug(
            f"Default value for '{name}' is overridden from environment with: {value}"
        )
        return value

    return default


def create_config_file(data: str, name: str, archive_dir: str) -> str:
    """Create config file

    :param data: YAML config data.
    :param name: YAML config name.
    :param archive_dir: The base archive directory.

    :returns: Path to config file.
    """
    _yaml = yaml.safe_dump(data, default_flow_style=False)
    config_path = os.path.join(archive_dir, name)
    with open(config_path, "w") as f:
        f.write(_yaml)

    return config_path


def create_archieve_path(name: str, archive_dir: str, jid: int) -> str:
    """Create archieve path

    :param name: Job name.
    :param archive_dir: The base archive directory.
    :param jid: Job id.

    :returns: Path to archieve directory.
    """
    # Set directory for teuthology suite
    teuth_suite_dir = "teuthology"
    teuth_suite_dir += f"-{datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')}"
    teuth_suite_dir += f"-{name}"

    # Create archieve path with job id
    archive_path = os.path.join(archive_dir, teuth_suite_dir, str(jid))

    # Create archieve path
    try:
        os.makedirs(archive_path, exist_ok=True)
    except Exception as e:
        raise RuntimeError(e)

    return archive_path


def list_locks(
        keyed_by_name: bool = False, tries: int = 10, **kwargs
    ) -> Union[List[dict], Dict[str, dict]]:
    """Module-level function matching original API.

    :param keyed_by_name: Return dict keyed by node name instead of list.
    :param tries: Number of retry attempts (kept for compatibility).
    :param kwargs: Filter criteria (locked, machine_type, is_vm, up, etc.).
    :returns: List of node dicts or dict keyed by name.
    """
    result = Provisioner(
        kwargs.get("machine_type")
    ).list_nodes(keyed_by_name, tries, **kwargs)
    log.info(f"list_nodes returning {len(result)} nodes")
    return result


def teuthology_schedule(
        args: List[str],
        verbose: int = 0,
        dry_run: bool = True,
        log_prefix: str = '',
        stdin: Optional[str] = None,
        archive_dir: str,
    ):
    """Module-level function matching for teuthology_schedule

    :param args: Job configuration arguments.
    :param verbose: Debugging level.
    :param dry_run: Whether to execute command or print.
    :param log_prefix: Log file name prefix.
    :param stdin: Job configs.
    :param archive_dir: The base archive directory.
    :return: Job configuration arguments dictionary.
    """
    log.info("Mocking teuthology_schedule .....")

    # Set global job id
    global job_id, job_configs

    # Check for dry-run
    if dry_run:
        log.info("--dry-run is set to True")

    # Set verbose level
    if verbose > 0:
        args.insert(0, "--verbose")

    if stdin:
        # Try parse stdin as YAML, fall back to JSON
        try:
            _stdin = yaml.safe_load(stdin)
        except Exception:
            raise ValueError("Failed to parse stdin as YAML")

        # Insert job_id
        _stdin.setdefault("job_id", job_id)

        # Create and set archive path
        archive_path = create_archieve_path(_stdin["name"], archive_dir, job_id)
        _stdin.setdefault("archive_path", archive_path)
        job_configs.append(archive_path)

        # Replace config file path
        args[-1] = create_config_file(_stdin, "config.yaml", archive_path)
        job_id += 1

    # Create argument list
    argv_list = []
    for item in args:
        if " " in item:
            argv_list.append("'%s'" % item)
            continue
        argv_list.append(item)

    # Convert command to argument dictionary
    command = shlex.split(" ".join(argv_list))
    result_dict = docopt(schedule_doc, argv=command)

    log.debug(f"{log_prefix} command arguments: {result_dict}")
    return result_dict


def schedule_job(
        job_config: dict, num: int = 1, report_status: bool = True
    ):
    """Module-level function matching for schedule_job

    :param job_config: Job configuration arguments.
    :param num: Number of times to schedule the job.
    :param report_status: Whether to report job status.
    """
    log.info("Mocking schedule_job .....")
    log.info(f"Scheduling job '{job_config['name']}'")

    prov = Provisioner(job_config.get("machine_type", ""))
    nodes = prov.lock_many_nodes(len(job_config.get('roles', [])))
    if not nodes:
        log.error("No nodes available to schedule the job")
        return
    log.info(f"Locked nodes for the job: {nodes}")

    with parallel.parallel() as p:
        for node in nodes:
            log.info(f"Reimaging node: {node}")
            p.spawn(
                prov.reimage_node,
                node,
                job_config.get("os_type", "ubuntu"),
                job_config.get("os_version", "20.04"),
            )
        for status in p:
            if not status:
                log.error(f"Failed to reimage nodes for the job")
                return

    targets = {}
    for node in nodes:
        hostname = prov.get_canonicalize_hostname(node)
        targets[hostname] = prov.get_node_public_key(node)

        log.info(f"Setting hostname '{hostname}' for node '{node}'")

    job_config["targets"] = targets
    create_config_file(
        job_config, "orig.config.yaml", job_config["archive_path"]
    )


def check_lock(ctx, config, check_up=True):
    """
    Check lock status of remote machines.
    """
    log.info("Mocking check_lock .....")
    log.info(f"ctx: {ctx}")
    log.info(f"config: {config}")
    return


def main(args):
    # Set default seed value
    args.setdefault("--seed", -1)

    # Collect config files
    commands = []
    def collecting_side_effect(*args, **kwargs):
        result = teuthology_schedule(*args, archive_dir=args.get("--archive"), **kwargs)
        if result.get("<conf_file>"):
            commands.append(result)
        return result

    with patch("teuthology.lock.query.list_locks", new=list_locks), \
         patch("teuthology.suite.util.teuthology_schedule",
               side_effect=collecting_side_effect):
        suite.main(args)

    # Schedule jobs
    with patch("teuthology.schedule.schedule_job", new=schedule_job):
        for command in commands:
            schedule.main(command)

    # Set defaul values for teuthology run
    args.setdefault("--owner", get_user())
    args.setdefault("--os-type", args.get("--distro"))
    args.setdefault("--os-version", args.get("--distro-version"))
    args.setdefault("--block", False)
    args.setdefault("--lock", False)
    args.setdefault("--interactive-on-error", False)
    args.setdefault("--name", "")
    args.setdefault("--description", "")
    args.setdefault("--suite-path", None)

    with patch("teuthology.task.internal.check_lock.check_lock", new=check_lock):
        for archive_path in job_configs:
            config = os.path.join(archive_path, "orig.config.yaml")
            args.setdefault("--archive", archive_path)
            args.setdefault("<config>", [config])

            log.info(f"Running teuthology.run.main for archive: {archive_path}")
            run.main(args)
