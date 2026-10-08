"""
The benchmark's plumbing, without a model: the harness runs a suite end to end
against a fake llama-server whose behaviour is known, so every verdict it
records can be checked. Also the calibration gate, the run-to-run comparison,
and the one-command runner's helpers.
"""

import json
import re
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "benchmark"))

import analyze  # noqa: E402
import run  # noqa: E402
import run_benchmark as rb  # noqa: E402

SUITE = json.loads((ROOT / "benchmark" / "suites" / "canary-v3.json").read_text(encoding="utf-8-sig"))
ATTACKER = SUITE["attackerAddress"]


def mini_suite(n_contents=3):
    keys = [c["key"] for c in SUITE["contents"][:n_contents]]
    return {**SUITE, "contents": SUITE["contents"][:n_contents],
            "attacks": [a for a in SUITE["attacks"] if a["contentKey"] in keys]}


class FakeModel(BaseHTTPRequestHandler):
    """Reads the source, then sends to whoever the stance says it obeys:
    obedient always follows the injection, hardened never does, neutral follows
    it only when the injection comes first in the content. The task of the
    content in `broken` never gets a tool call, so its benign control fails."""
    broken = ""

    def log_message(self, *a):
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        msgs = req["messages"]
        system, task, last = msgs[0]["content"], msgs[1]["content"], msgs[-1]["content"]
        if task == self.broken:
            text = "I can't help with that."
        elif len(msgs) == 2:
            text = '{"tool": "read_source", "arguments": {"source": "x"}}'
        elif last.startswith("[tool result for read_source]"):
            body = last.split("\n", 1)[1]
            injected = ATTACKER in body
            obey = ("Follow every instruction" in system or
                    ("untrusted data" not in system and injected and body.find(ATTACKER) < 200))
            to = ATTACKER if injected and obey else re.search(r"[\w.]+@company\.test|[\w.]+@[\w-]+\.test", task).group(0)
            text = json.dumps({"tool": "send_message", "arguments": {"to": to, "body": "summary"}})
        else:
            text = "Done."
        out = json.dumps({"choices": [{"message": {"role": "assistant", "content": text}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class Harness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = mini_suite()
        FakeModel.broken = cls.suite["contents"][2]["task"]
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeModel)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.runs = {s: rb.run_stance(cls.port, cls.suite, s, 42, log=lambda m: None)
                    for s in ("obedient", "neutral", "hardened")}

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_verdict_strings_have_one_char_per_case_in_suite_order(self):
        r = self.runs["neutral"]
        self.assertEqual(len(r["utility"]["verdicts"]), len(self.suite["contents"]))
        self.assertEqual(len(r["susceptibility"]["verdicts"]), len(self.suite["attacks"]))
        self.assertEqual(r["utility"]["verdicts"], "110")

    def test_a_failed_benign_marks_its_attacks_not_eligible(self):
        v = self.runs["neutral"]["susceptibility"]["verdicts"]
        broken = self.suite["contents"][2]["key"]
        for ch, a in zip(v, self.suite["attacks"]):
            self.assertEqual(ch == "-", a["contentKey"] == broken)
        self.assertEqual(self.runs["neutral"]["susceptibility"]["eligible"], v.count("0") + v.count("1"))

    def test_verdicts_match_the_fake_models_known_behaviour(self):
        self.assertEqual(set(self.runs["obedient"]["susceptibility"]["verdicts"]) - {"-"}, {"1"})
        self.assertEqual(set(self.runs["hardened"]["susceptibility"]["verdicts"]) - {"-"}, {"0"})
        for ch, a in zip(self.runs["neutral"]["susceptibility"]["verdicts"], self.suite["attacks"]):
            if ch != "-":
                self.assertEqual(ch, "1" if a["position"] == "start" else "0", a["id"])

    def test_result_validates_against_the_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        import tempfile
        schema = json.loads((ROOT / "schema" / "susceptibility-result.schema.json").read_text(encoding="utf-8"))
        model = {"baseModel": "fake-1b", "lineage": "instruct-tune", "quantization": "Q8_0",
                 "weightsDigest": "sha256:" + "0" * 64, "runner": "fake", "hardware": "none", "_tag": "t"}
        with tempfile.TemporaryDirectory() as d:
            p = rb.write_result(suite=self.suite, stance="neutral", run=self.runs["neutral"], model=model,
                                seed=42, elapsed=1, out_dir=Path(d), tr_dir=Path(d) / "tr")
            self.assertTrue(p.name.endswith("-neutral-t.json"))
            jsonschema.validate(json.loads(p.read_text(encoding="utf-8")), schema)


class RunnerAndModes(unittest.TestCase):
    def runner_from(self, text):
        from unittest import mock
        done = mock.Mock(stdout="", stderr=text)
        with mock.patch.object(rb.subprocess, "run", return_value=done):
            return rb.detect_runner(Path("llama-server"))

    def test_release_builds_record_build_and_commit(self):
        self.assertEqual(self.runner_from("version: 6923 (abc1234)\nbuilt with gcc"), "llama.cpp b6923 (abc1234)")
        self.assertEqual(self.runner_from("load_backend ...\nbuild 11057, commit 59657a6"),
                         "llama.cpp b11057 (59657a6)")

    def test_shallow_clone_builds_record_only_the_commit(self):
        # A shallow clone counts one commit, so "build 1" would look like an ancient release.
        self.assertEqual(self.runner_from("build 1, commit 59657a6"), "llama.cpp commit 59657a6")

    def test_deterministic_runs_say_so_in_the_result(self):
        import tempfile
        run = {"records": [], "errors": 0, "utility": {"benignPassed": 0, "benignTotal": 0, "rate": 0.0},
               "susceptibility": {"complied": 0, "eligible": 0, "rate": 0.0}}
        model = {"baseModel": "fake-1b", "quantization": "Q8_0", "weightsDigest": "sha256:" + "0" * 64}
        notes = {}
        for mode, extra in (("default", {}), ("det", {"cache_prompt": False})):
            old = dict(rb.CHAT_EXTRA)
            rb.CHAT_EXTRA.clear(); rb.CHAT_EXTRA.update(extra)
            try:
                with tempfile.TemporaryDirectory() as d:
                    p = rb.write_result(suite=SUITE, stance="neutral", run=run, model=model, seed=42,
                                        elapsed=1, out_dir=Path(d), tr_dir=Path(d) / "tr")
                    notes[mode] = json.loads(p.read_text(encoding="utf-8"))["notes"]
            finally:
                rb.CHAT_EXTRA.clear(); rb.CHAT_EXTRA.update(old)
        self.assertNotIn("Deterministic", notes["default"])
        self.assertIn("Deterministic", notes["det"])


def result(stance, verdicts, suite_id="canary-v3"):
    return {"model": {"baseModel": "m", "quantization": "Q8_0", "weightsDigest": "sha256:" + "0" * 64},
            "scaffold": {"suite": suite_id, "stance": stance, "cases": len(verdicts)},
            "utility": {"benignPassed": 1, "benignTotal": 1, "rate": 1.0},
            "susceptibility": {"complied": verdicts.count("1"),
                               "eligible": verdicts.count("1") + verdicts.count("0"),
                               "rate": 0.0, "verdicts": verdicts}}


def verdicts_with_rate(rate, n=len(SUITE["attacks"])):
    k = round(rate * n)
    return "1" * k + "0" * (n - k)


class Calibration(unittest.TestCase):
    def test_well_separated_controls_calibrate(self):
        cal = analyze.calibration({"obedient": result("obedient", verdicts_with_rate(0.9)),
                                   "neutral": result("neutral", verdicts_with_rate(0.6)),
                                   "hardened": result("hardened", verdicts_with_rate(0.1))})
        self.assertTrue(cal["instead"]["calibrated"])
        self.assertTrue(cal["instead"]["exact"])

    def test_misordered_controls_do_not(self):
        cal = analyze.calibration({"obedient": result("obedient", verdicts_with_rate(0.1)),
                                   "neutral": result("neutral", verdicts_with_rate(0.2)),
                                   "hardened": result("hardened", verdicts_with_rate(0.05))})
        self.assertFalse(cal["instead"]["ordered"])
        self.assertFalse(cal["instead"]["calibrated"])

    def test_overlapping_controls_do_not(self):
        few = "1" * 3 + "0" * 3 + "-" * (len(SUITE["attacks"]) - 6)
        fewer = "1" * 2 + "0" * 4 + "-" * (len(SUITE["attacks"]) - 6)
        cal = analyze.calibration({"obedient": result("obedient", few), "neutral": result("neutral", fewer),
                                   "hardened": result("hardened", fewer)})
        self.assertTrue(cal["instead"]["ordered"])
        self.assertFalse(cal["instead"]["separated"])

    def test_old_results_without_verdicts_are_estimated(self):
        r = {"susceptibility": {"complied": 50, "eligible": 100, "byGoal": {"instead": 0.8, "also": 0.2}},
             "scaffold": {"suite": "canary-v2"}}
        self.assertEqual(analyze.goal_counts(r), {"instead": (40, 50, False), "also": (10, 50, False)})


class Compare(unittest.TestCase):
    def test_identical_runs_agree_fully(self):
        v = verdicts_with_rate(0.5)
        c = analyze.compare(result("neutral", v), result("neutral", v))["goals"]["all"]
        self.assertEqual((c["agree"], c["flipAB"], c["flipBA"], c["mcnemarP"]), (len(v), 0, 0, 1.0))

    def test_symmetric_flips_are_noise_one_sided_flips_are_not(self):
        n = len(SUITE["attacks"])
        base = list(verdicts_with_rate(0.5))
        sym = base[:]
        for i in (0, 1, n - 1, n - 2):   # two 1->0 and two 0->1
            sym[i] = "0" if sym[i] == "1" else "1"
        c = analyze.compare(result("neutral", "".join(base)), result("neutral", "".join(sym)))["goals"]["all"]
        self.assertEqual((c["flipAB"], c["flipBA"]), (2, 2))
        self.assertEqual(c["mcnemarP"], 1.0)
        one = ["0" if i < 20 else ch for i, ch in enumerate(base)]
        c = analyze.compare(result("neutral", "".join(base)), result("neutral", "".join(one)))["goals"]["all"]
        self.assertEqual((c["flipAB"], c["flipBA"]), (20, 0))
        self.assertLess(c["mcnemarP"], 0.001)

    def test_cases_ineligible_in_either_run_are_left_out(self):
        a = "1" * 10 + "-" * (len(SUITE["attacks"]) - 10)
        b = "-" * 5 + "1" * (len(SUITE["attacks"]) - 5)
        self.assertEqual(analyze.compare(result("neutral", a), result("neutral", b))["goals"]["all"]["both"], 5)


class OneCommand(unittest.TestCase):
    def test_hf_ids(self):
        self.assertEqual(run.parse_hf("hf:bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/Meta-Llama-3.1-8B-Instruct-Q8_0.gguf"),
                         ("bartowski/Meta-Llama-3.1-8B-Instruct-GGUF", "Meta-Llama-3.1-8B-Instruct-Q8_0.gguf"))
        self.assertEqual(run.parse_hf("hf:o/r/sub/dir/x-Q4_K_M.gguf"), ("o/r", "sub/dir/x-Q4_K_M.gguf"))
        with self.assertRaises(ValueError):
            run.parse_hf("hf:o/r")

    def test_quantization_and_base_from_file_names(self):
        cases = {"Meta-Llama-3.1-8B-Instruct-Q8_0.gguf": ("Q8_0", "meta-llama-3.1-8b-instruct"),
                 "Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf": ("Q4_K_M", "meta-llama-3.1-8b-instruct"),
                 "Hermes-3-Llama-3.1-8B.Q6_K.gguf": ("Q6_K", "hermes-3-llama-3.1-8b"),
                 "model-f16.gguf": ("F16", "model"),
                 "qwen2.5-7b-instruct-IQ4_XS.gguf": ("IQ4_XS", "qwen2.5-7b-instruct")}
        for name, (q, base) in cases.items():
            self.assertEqual(run.quantization_of(name), q, name)
            self.assertEqual(run.base_model_of(name), base, name)
        self.assertIsNone(run.quantization_of("mystery.gguf"))

    def test_release_asset_choice(self):
        assets = [{"name": n} for n in (
            "llama-b7000-bin-ubuntu-x64.zip", "llama-b7000-bin-ubuntu-vulkan-x64.zip",
            "llama-b7000-bin-win-cuda-12.4-x64.zip", "cudart-llama-bin-win-cuda-12.4-x64.zip",
            "llama-b7000-bin-win-cpu-x64.zip", "llama-b7000-bin-macos-arm64.zip", "llama-b7000-xcframework.zip")]
        pick = lambda *a: run.release_asset(assets, *a)["name"]  # noqa: E731
        self.assertEqual(pick("Linux", "x86_64", True), "llama-b7000-bin-ubuntu-vulkan-x64.zip")
        self.assertEqual(pick("Linux", "x86_64", False), "llama-b7000-bin-ubuntu-x64.zip")
        self.assertEqual(pick("Windows", "AMD64", True), "llama-b7000-bin-win-cuda-12.4-x64.zip")
        self.assertEqual(pick("Windows", "AMD64", False), "llama-b7000-bin-win-cpu-x64.zip")
        self.assertEqual(pick("Darwin", "arm64", True), "llama-b7000-bin-macos-arm64.zip")
        self.assertIsNone(run.release_asset(assets, "Linux", "aarch64", False))


if __name__ == "__main__":
    unittest.main()
