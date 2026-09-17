"""Phase 3 — MLShield baseline pipeline DAG.

Automates: ingest -> validate -> train -> evaluate -> register, replacing
the manual step-by-step execution from Phases 1-2. Each task shells out to
the project's ML virtualenv (kept separate from Airflow's own venv — see
progress.md Phase 3 notes on why) and runs one of the src/pipeline/*.py
steps. Airflow's own task dependency/failure semantics are what enforce
"a broken run halts the pipeline instead of registering a bad model" -
if `validate` or `evaluate` fails, downstream tasks never run at all.

To exercise the deliberate-failure test path, trigger this DAG with a conf
that points ingest at a corrupted file, e.g.:
    airflow dags test mlshield_baseline <date> \
        --conf '{"train_source_override": "/path/to/corrupted_file.txt"}'
"""
from datetime import datetime

from airflow import DAG
from airflow.operators.bash import BashOperator

REPO_ROOT = "/home/user/MLopsCP"
ML_VENV_PYTHON = f"{REPO_ROOT}/.venv/bin/python"

default_args = {
    "owner": "mlshield",
    "retries": 0,  # no silent retries masking a real failure during the gate test
}

with DAG(
    dag_id="mlshield_baseline",
    description="Ingest -> validate -> train -> evaluate -> register (Phase 3)",
    default_args=default_args,
    schedule=None,  # triggered manually / by `airflow dags test` for now
    start_date=datetime(2026, 1, 1),
    catchup=False,
    tags=["mlshield", "phase3"],
) as dag:

    ingest = BashOperator(
        task_id="ingest",
        bash_command=(
            "cd {{ params.repo_root }} && "
            "MLSHIELD_INGEST_TRAIN_SOURCE='{{ dag_run.conf.get(\"train_source_override\", \"\") if dag_run and dag_run.conf else \"\" }}' "
            "{{ params.python }} -m src.pipeline.ingest"
        ),
        params={"repo_root": REPO_ROOT, "python": ML_VENV_PYTHON},
    )

    validate = BashOperator(
        task_id="validate",
        bash_command="cd {{ params.repo_root }} && {{ params.python }} -m src.pipeline.validate",
        params={"repo_root": REPO_ROOT, "python": ML_VENV_PYTHON},
    )

    train = BashOperator(
        task_id="train",
        bash_command="cd {{ params.repo_root }} && MLFLOW_DISABLE_AGENT_HINT=1 {{ params.python }} -m src.pipeline.train",
        params={"repo_root": REPO_ROOT, "python": ML_VENV_PYTHON},
    )

    evaluate = BashOperator(
        task_id="evaluate",
        bash_command="cd {{ params.repo_root }} && {{ params.python }} -m src.pipeline.evaluate",
        params={"repo_root": REPO_ROOT, "python": ML_VENV_PYTHON},
    )

    register = BashOperator(
        task_id="register",
        bash_command="cd {{ params.repo_root }} && MLFLOW_DISABLE_AGENT_HINT=1 {{ params.python }} -m src.pipeline.register",
        params={"repo_root": REPO_ROOT, "python": ML_VENV_PYTHON},
    )

    ingest >> validate >> train >> evaluate >> register
