from __future__ import annotations

import json
import multiprocessing
import os
import signal
import unittest

from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import AGENTS_DIRECTORY, AgentEnvironment, REPOSITORY_ROOT


def _load_agent(data: str, generated: str, name: str):
    os.environ.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "RAPP_STACK_ROOT": str(REPOSITORY_ROOT),
            "RAPP_STACK_DATA_DIR": data,
            "RAPP_STACK_GENERATED_AGENTS_DIR": generated,
            "RAPP_STACK_PRINCIPAL": "principal-a",
            "RAPP_STACK_ALLOW_AGENT_WRITES": "1",
        }
    )
    return AgentRegistry(
        AGENTS_DIRECTORY,
        storage=LocalStorage(data),
    ).load()[name]


def _memory_worker(data, generated, start, results, index):
    agent = _load_agent(data, generated, "Memory")
    start.wait(10)
    value = agent.perform(
        action="remember",
        content=f"Concurrent synthetic fact {index}.",
        tags=["context"],
        importance=4,
        timestamp=f"2026-01-01T00:00:{index:02d}Z",
    )
    results.put(json.loads(value))


def _factory_worker(
    data,
    generated,
    start,
    results,
    expected_digest,
    description,
):
    agent = _load_agent(data, generated, "AgentFactory")
    start.wait(10)
    value = agent.perform(
        action="create",
        name="ConcurrentSample",
        description=description,
        parameters=[],
        expected_digest=expected_digest,
    )
    results.put(json.loads(value))


class CrossProcessAgentTransactionTests(unittest.TestCase):
    def test_memory_remember_has_no_cross_process_lost_updates(self):
        with AgentEnvironment(writes=True) as environment:
            context = multiprocessing.get_context("fork")
            start = context.Event()
            results = context.Queue()
            processes = [
                context.Process(
                    target=_memory_worker,
                    args=(
                        str(environment.data),
                        str(environment.generated),
                        start,
                        results,
                        index,
                    ),
                )
                for index in range(8)
            ]
            for process in processes:
                process.start()
            start.set()
            observed = [results.get(timeout=20) for _ in processes]
            self._join(processes)

            self.assertTrue(
                all(item.get("status") == "stored" for item in observed),
                observed,
            )
            memory = environment.snapshot["Memory"]
            listed = json.loads(memory.perform(action="list", limit=20))
            self.assertEqual(listed["total_count"], len(processes))
            self.assertEqual(
                len({item["id"] for item in listed["memories"]}),
                len(processes),
            )

    def test_factory_digest_cas_allows_only_one_cross_process_overwrite(self):
        with AgentEnvironment(writes=True) as environment:
            factory = environment.snapshot["AgentFactory"]
            initial = json.loads(
                factory.perform(
                    action="create",
                    name="ConcurrentSample",
                    description="Initial synthetic source.",
                    parameters=[],
                )
            )
            self.assertEqual(initial["status"], "created")

            context = multiprocessing.get_context("fork")
            start = context.Event()
            results = context.Queue()
            processes = [
                context.Process(
                    target=_factory_worker,
                    args=(
                        str(environment.data),
                        str(environment.generated),
                        start,
                        results,
                        initial["sha256"],
                        description,
                    ),
                )
                for description in (
                    "First concurrent replacement.",
                    "Second concurrent replacement.",
                )
            ]
            for process in processes:
                process.start()
            start.set()
            observed = [results.get(timeout=20) for _ in processes]
            self._join(processes)

            self.assertEqual(
                sum(item.get("status") == "updated" for item in observed), 1
            )
            self.assertEqual(
                sum(
                    item.get("error", {}).get("code") == "digest_conflict"
                    for item in observed
                ),
                1,
            )
            path = environment.generated / "concurrent_sample_agent.py"
            loaded = AgentRegistry(
                environment.generated,
                storage=LocalStorage(environment.data),
            ).load()
            self.assertEqual(loaded.names, ("ConcurrentSample",))
            self.assertTrue(path.is_file())

    def _join(self, processes) -> None:
        for process in processes:
            process.join(20)
        for process in processes:
            if process.is_alive():
                os.kill(process.pid, signal.SIGTERM)
                process.join(5)
            self.assertEqual(process.exitcode, 0)


if __name__ == "__main__":
    unittest.main()
