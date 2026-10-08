#!/usr/bin/env python3
"""
One command: a model id in, a valid susceptibility result out.

    python benchmark/run.py hf:bartowski/Meta-Llama-3.1-8B-Instruct-GGUF/Meta-Llama-3.1-8B-Instruct-Q8_0.gguf \
        --base-model llama-3.1-8b-instruct

It fetches the GGUF (resumable, cached), hashes it and checks the hash against the
one HuggingFace publishes, finds llama-server (or downloads an official llama.cpp
release with --get-llama), runs the suite under the measurement scaffold and both
controls, writes one result per stance to benchmark/results/, and prints the
calibration summary. A local .gguf path works in place of an hf: id.

Standard library only. See SPEC.md for what is measured and why.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run_benchmark as rb  # noqa: E402
import analyze  # noqa: E402

CACHE = Path(os.environ.get("AVE_CACHE", Path.home() / ".cache" / "ave"))
QUANT = re.compile(r"(?i)(?<![A-Za-z0-9])(IQ\d_[A-Z]+|Q\d_K_[SML]|Q\d_K|Q\d_\d|BF16|FP16|F16|F32)(?![A-Za-z0-9])")


# ── model id → local file ────────────────────────────────────────────────────

def parse_hf(spec: str) -> tuple[str, str]:
    """'hf:owner/repo/path/file.gguf' -> ('owner/repo', 'path/file.gguf')."""
    if not spec.startswith("hf:"):
        raise ValueError(spec)
    parts = spec[3:].split("/")
    if len(parts) < 3 or not parts[-1].lower().endswith(".gguf"):
        raise ValueError(f"expected hf:<owner>/<repo>/<file>.gguf, got {spec}")
    return "/".join(parts[:2]), "/".join(parts[2:])


def quantization_of(filename: str) -> str | None:
    m = QUANT.search(Path(filename).stem)
    return m.group(1).upper().replace("FP16", "F16") if m else None


def base_model_of(filename: str) -> str:
    """'Meta-Llama-3.1-8B-Instruct-Q8_0.gguf' -> 'meta-llama-3.1-8b-instruct'. A guess for
    grouping only; pass --base-model to group results from different repos together."""
    stem = Path(filename).stem
    q = QUANT.search(stem)
    if q:
        stem = stem[:q.start()]
    return stem.strip("-_. ").lower()


def hf_sha256(repo: str, path: str) -> str | None:
    """The LFS sha256 HuggingFace publishes for a file, or None if it can't be had."""
    url = f"https://huggingface.co/api/models/{repo}/tree/main/{'/'.join(path.split('/')[:-1])}".rstrip("/")
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            for entry in json.loads(r.read()):
                if entry.get("path") == path and entry.get("lfs"):
                    return entry["lfs"].get("oid") or entry["lfs"].get("sha256")
    except Exception as e:
        print(f"  (could not read the published hash: {e})")
    return None


def download(url: str, dest: Path) -> None:
    """Resumable download to dest (via dest.part)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_name(dest.name + ".part")
    have = part.stat().st_size if part.exists() else 0
    req = urllib.request.Request(url, headers={"Range": f"bytes={have}-"} if have else {})
    with urllib.request.urlopen(req, timeout=60) as r:
        if have and r.status != 206:
            have = 0  # server ignored the range: start over
        total = have + int(r.headers.get("Content-Length") or 0)
        t0, last = time.time(), 0.0
        with open(part, "ab" if have else "wb") as f:
            done = have
            while chunk := r.read(1 << 20):
                f.write(chunk)
                done += len(chunk)
                if time.time() - last > 5:
                    last = time.time()
                    rate = (done - have) / max(time.time() - t0, 1e-6) / 1e6
                    pct = f"{100 * done / total:.0f}%" if total else f"{done / 1e9:.1f} GB"
                    print(f"  downloading {dest.name}: {pct} at {rate:.0f} MB/s", flush=True)
    part.rename(dest)


def sha256_of(path: Path) -> str:
    """Hash once; cached next to the file and keyed by size and mtime."""
    st = path.stat()
    memo = path.with_name(path.name + ".sha256")
    key = f"{st.st_size}:{int(st.st_mtime)}"
    if memo.exists():
        k, _, h = memo.read_text().strip().partition(" ")
        if k == key:
            return h
    print(f"  hashing {path.name}...", flush=True)
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 24):
            h.update(chunk)
    digest = h.hexdigest()
    try:
        memo.write_text(f"{key} {digest}\n")
    except OSError:
        pass
    return digest


def fetch_model(spec: str) -> tuple[Path, str, str]:
    """(local path, sha256 hex, sourceUri)."""
    if not spec.startswith("hf:"):
        p = Path(spec).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(p)
        return p, sha256_of(p), ""
    repo, path = parse_hf(spec)
    dest = CACHE / "models" / repo / path
    if not dest.exists():
        download(f"https://huggingface.co/{repo}/resolve/main/{path}", dest)
    digest = sha256_of(dest)
    published = hf_sha256(repo, path)
    if published and published != digest:
        raise SystemExit(f"hash mismatch for {path}: file {digest}, HuggingFace says {published}. "
                         f"Delete {dest} and run again.")
    if published:
        print(f"  sha256 matches HuggingFace: {digest[:16]}...")
    return dest, digest, spec


# ── llama-server ─────────────────────────────────────────────────────────────

def release_asset(assets: list[dict], system: str, machine: str, gpu: bool) -> dict | None:
    """Pick the official llama.cpp release zip for this platform. Asset names follow
    'llama-b<N>-bin-<platform>.zip'; prefer a GPU build when one is wanted."""
    names = {a["name"]: a for a in assets if a["name"].endswith(".zip") and "-bin-" in a["name"]}
    arm = machine.lower() in ("arm64", "aarch64")
    if system == "Darwin":
        want = ["macos-arm64"] if arm else ["macos-x64"]
    elif system == "Windows":
        want = (["win-cuda-12", "win-vulkan-x64"] if gpu else []) + (["win-cpu-arm64"] if arm else ["win-cpu-x64"])
    else:
        want = (["ubuntu-vulkan-x64"] if gpu and not arm else []) + (["ubuntu-arm64"] if arm else ["ubuntu-x64"])
    for w in want:
        for name, a in sorted(names.items()):
            if w in name and "cudart" not in name:
                return a
    return None


def get_llama(gpu: bool) -> Path:
    """Download the latest official llama.cpp release into the cache; return its bin dir."""
    with urllib.request.urlopen("https://api.github.com/repos/ggml-org/llama.cpp/releases/latest",
                                timeout=30) as r:
        rel = json.loads(r.read())
    asset = release_asset(rel.get("assets", []), platform.system(), platform.machine(), gpu)
    if not asset:
        raise SystemExit("no llama.cpp release build for this platform; build llama.cpp and pass --llama-bin")
    root = CACHE / "llama.cpp" / rel["tag_name"] / asset["name"][:-4]
    if not root.exists():
        z = root.with_suffix(".zip")
        download(asset["browser_download_url"], z)
        with zipfile.ZipFile(z) as f:
            f.extractall(root)
        z.unlink()
        if "win-cuda" in asset["name"]:  # the CUDA runtime ships as a separate zip
            for a in rel.get("assets", []):
                if a["name"].startswith("cudart") and "win" in a["name"]:
                    z = root / a["name"]
                    download(a["browser_download_url"], z)
                    with zipfile.ZipFile(z) as f:
                        f.extractall(root)
                    z.unlink()
                    break
    exe = next((p for p in root.rglob("llama-server*") if p.is_file()), None)
    if not exe:
        raise SystemExit(f"llama-server missing from {asset['name']}")
    if os.name != "nt":
        for p in exe.parent.iterdir():
            if p.is_file():
                p.chmod(p.stat().st_mode | 0o111)
    print(f"  llama.cpp {rel['tag_name']} ({asset['name']})")
    return exe.parent


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("model", help="hf:<owner>/<repo>/<file>.gguf, or a local .gguf path")
    ap.add_argument("--base-model", help="family and size for grouping, e.g. llama-3.1-8b-instruct "
                                         "(default: guessed from the file name)")
    ap.add_argument("--lineage", default="instruct-tune",
                    choices=["base", "instruct-tune", "community-finetune", "abliterated"])
    ap.add_argument("--quant", help="quantization label (default: from the file name)")
    ap.add_argument("--scaffold", default="all", choices=list(rb.STANCES) + ["all"],
                    help="'all' (default) runs the measurement and both calibration controls")
    ap.add_argument("--suite", default=str(HERE / "suites" / "canary-v3.json"))
    ap.add_argument("--llama-bin", help="llama.cpp dir with llama-server (default: PATH)")
    ap.add_argument("--get-llama", action="store_true",
                    help="download the latest official llama.cpp release if llama-server isn't found")
    ap.add_argument("--cpu", action="store_true", help="run on the CPU only (no GPU offload)")
    ap.add_argument("--deterministic", action="store_true",
                    help="one server slot and no prompt-cache reuse, so repeat runs can match case by case")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--port", type=int, default=8177)
    ap.add_argument("--ctx", type=int, default=8192)
    ap.add_argument("--runner", help="recorded runner, e.g. 'llama.cpp b11057' (default: detected)")
    ap.add_argument("--tag", help="suffix for the result file names, to keep repeat runs apart")
    ap.add_argument("--ran-by", help="your handle, recorded in the result")
    ap.add_argument("--out-dir", default=str(HERE / "results"))
    ap.add_argument("--transcript-dir", default=str(HERE / "transcripts"))
    args = ap.parse_args()

    print(f"[1/3] model  {args.model}")
    path, digest, source = fetch_model(args.model)
    quant = args.quant or quantization_of(path.name)
    if not quant:
        raise SystemExit(f"can't tell the quantization from {path.name}; pass --quant")
    base = args.base_model or base_model_of(path.name)

    print("[2/3] runner")
    ngl = 0 if args.cpu else 99
    try:
        exe = rb.server_exe(args.llama_bin)
    except FileNotFoundError as e:
        if not args.get_llama:
            raise SystemExit(f"{e}\n(or add --get-llama to download an official llama.cpp release)")
        exe = rb.server_exe(get_llama(gpu=not args.cpu))
    runner = args.runner or rb.detect_runner(exe)
    hardware = rb.detect_hardware(ngl)
    print(f"  {runner} on {hardware}")

    suite = json.loads(Path(args.suite).read_text(encoding="utf-8-sig"))
    stances = ["obedient", "neutral", "hardened"] if args.scaffold == "all" else [args.scaffold]
    model = {"baseModel": base, "lineage": args.lineage, "quantization": quant,
             "weightsDigest": "sha256:" + digest, "sourceUri": source,
             "runner": runner, "hardware": hardware, "_tag": args.tag}
    print(f"[3/3] {suite['suiteId']}: {len(suite['attacks'])} attacks x {len(stances)} stance(s)  "
          f"{base} {quant} ({args.lineage})")
    # A GPU build still offloads big matrix multiplies to the GPU at -ngl 0;
    # --device none keeps a CPU run on the CPU.
    extra = ["--device", "none"] if args.cpu else []
    if args.deterministic:
        extra += ["-np", "1"]
        rb.CHAT_EXTRA["cache_prompt"] = False
    proc = rb.start_server(exe.parent, path, args.port, ngl, args.ctx, extra=extra)
    written = []
    try:
        for stance in stances:
            t1 = time.time()
            print(f"--- {stance}", flush=True)
            run = rb.run_stance(args.port, suite, stance, args.seed, log=lambda m: print(m, flush=True))
            written.append(rb.write_result(suite=suite, stance=stance, run=run, model=model, seed=args.seed,
                                           elapsed=time.time() - t1, out_dir=Path(args.out_dir),
                                           tr_dir=Path(args.transcript_dir), ran_by=args.ran_by))
            s = run["susceptibility"]
            print(f"  {stance}: {s['complied']}/{s['eligible']} complied ({s['rate']:.1%}), "
                  f"utility {run['utility']['benignPassed']}/{run['utility']['benignTotal']}", flush=True)
    finally:
        rb.stop_server(proc)

    print()
    for p in written:
        print(f"wrote {p.relative_to(HERE.parent) if p.is_relative_to(HERE.parent) else p}")
    print()
    analyze.report([json.loads(p.read_text(encoding="utf-8")) for p in written])
    return 0


if __name__ == "__main__":
    sys.exit(main())
