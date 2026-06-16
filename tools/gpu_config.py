import os
import subprocess
import ollama as _ollama


def _free_vram_mb() -> int:
    """Return the largest contiguous free VRAM block across all GPUs, in MiB."""
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return 0
        values = [int(x.strip()) for x in result.stdout.strip().splitlines() if x.strip().isdigit()]
        return max(values) if values else 0
    except Exception:
        return 0


def get_num_gpu() -> int:
    """
    Return the num_gpu value to pass to ollama options.

    Thresholds (based on qwen3:32b Q4_K_M ≈ 19 GB):
      >= 18 000 MiB  → full GPU  (99 = "use all layers")
       8 000–18 000  → partial   (40 layers, rest on CPU)
      < 8 000        → CPU only  (0)

    Override with env ATMG_NUM_GPU (e.g. ATMG_NUM_GPU=0 for CPU-only).
    """
    env_override = os.environ.get("ATMG_NUM_GPU")
    if env_override is not None:
        try:
            return int(env_override)
        except ValueError:
            pass

    free = _free_vram_mb()
    if free == 0:
        # nvidia-smi unavailable — assume GPU present and let ollama decide
        return 99
    if free >= 18_000:
        return 99   # full GPU
    if free >= 8_000:
        print(f"[GPU] Only {free} MiB free — using partial GPU offload (40 layers)")
        return 40
    print(f"[GPU] Only {free} MiB free — falling back to CPU")
    return 0


# Cached so we only query nvidia-smi once per process. Kept for callers that
# still ask for a default value before the model name is known.
_NUM_GPU: int | None = None

# Cache successful offload per model. The 51GB coder model and 20GB/29GB qwen3
# model fit differently; a single global cache can pin every later model to the
# coder model's low fallback.
_MODEL_GPU: dict[str, int] = {}

# Fallback ladder: full GPU → progressively smaller offloads → CPU.
_GPU_FALLBACK = [99, 80, 70, 60, 50, 40, 30, 20, 0]

# Known-good campaign pins. These avoid silent GPU/CPU drift during seeded
# reproducibility runs while keeping the published model choices unchanged.
_MODEL_GPU_FIXED = {
    "qwen3-coder-next:q4_K_M": 20,
    "qwen3:32b": 99,
    "gemma2:27b": 99,
}


def _num_ctx() -> int:
    """Return Ollama context size. Smaller context allows more GPU offload."""
    raw = os.environ.get("ATMG_NUM_CTX", "8192")
    try:
        return int(raw)
    except ValueError:
        return 8192


def num_gpu() -> int:
    global _NUM_GPU
    if _NUM_GPU is None:
        _NUM_GPU = get_num_gpu()
        mode = "full GPU" if _NUM_GPU == 99 else ("CPU" if _NUM_GPU == 0 else f"partial ({_NUM_GPU} layers)")
        print(f"[GPU] ollama num_gpu={_NUM_GPU} ({mode})")
    return _NUM_GPU


def ollama_chat(model: str, messages: list, options: dict, keep_alive="24h") -> dict:
    """
    Drop-in replacement for ollama.chat with automatic GPU fallback.

    On a 500 / memory error the call is retried at each level of
    _GPU_FALLBACK until one succeeds or all are exhausted.
    The cached num_gpu value is updated so subsequent calls skip
    the failing level automatically.
    """
    global _NUM_GPU

    if os.environ.get("ATMG_NO_FALLBACK"):
        gpu_val = _MODEL_GPU_FIXED.get(model, int(os.environ.get("ATMG_NUM_GPU", 99)))
        opts = {**options, "num_gpu": gpu_val, "num_ctx": _num_ctx()}
        print(f"[GPU] {model} using fixed num_gpu={gpu_val}, num_ctx={opts['num_ctx']} (no fallback)")
        result = _ollama.chat(model=model, messages=messages,
                              options=opts, keep_alive=keep_alive)
        _MODEL_GPU[model] = gpu_val
        _NUM_GPU = gpu_val
        return result

    start = _MODEL_GPU.get(model)
    if start is None:
        start = int(os.environ.get("ATMG_NUM_GPU", num_gpu()))
    ladder = [v for v in _GPU_FALLBACK if v <= start] or [0]

    last_exc = None
    for gpu_val in ladder:
        opts = {**options, "num_gpu": gpu_val, "num_ctx": _num_ctx()}
        try:
            result = _ollama.chat(model=model, messages=messages,
                                  options=opts, keep_alive=keep_alive)
            if gpu_val != start:
                print(f"[GPU] {model} fell back to num_gpu={gpu_val} — updating model cache")
            else:
                print(f"[GPU] {model} using num_gpu={gpu_val}, num_ctx={opts['num_ctx']}")
            _MODEL_GPU[model] = gpu_val
            _NUM_GPU = gpu_val
            return result
        except Exception as exc:
            msg = str(exc).lower()
            if "500" in msg or "memory" in msg or "cannot be allocated" in msg:
                print(f"[GPU] num_gpu={gpu_val} → memory error, trying next level…")
                last_exc = exc
                continue
            raise  # non-memory error: surface immediately

    raise RuntimeError(f"All GPU fallback levels failed. Last error: {last_exc}")
