import os
import subprocess
import tempfile
import shutil

# ── DOCKER IMAGES ─────────────────────────────────────────────────────────────
IMAGES = {
    "python": "python:3.12-slim",
    "java":   "eclipse-temurin:17-jdk-jammy",
    "c++":    "gcc:13",
    "cpp":    "gcc:13",
}

TIMEOUT_SECONDS = 30
MEMORY_LIMIT    = "512m"
CPU_LIMIT       = "0.5"


def _java_string(s: str) -> str:
    """
    Escape a Python string for safe injection into a Java string literal.
    Python repr() uses single quotes for strings without single quotes,
    which is invalid Java. This always produces a valid Java string body.
    """
    return (s
        .replace("\\", "\\\\")
        .replace('"',  '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def run_in_sandbox(
    code:     str,
    payload:  str,
    language: str,
    timeout:  int = TIMEOUT_SECONDS
) -> dict:
    lang  = language.lower().strip()
    image = IMAGES.get(lang)

    if not image:
        return {
            "confirmed": False,
            "output":    "",
            "error":     f"Unsupported language: {language}",
            "exit_code": -1,
            "timed_out": False,
            "payload":   payload,
            "language":  language
        }

    temp_dir = tempfile.mkdtemp(prefix="atmg_sandbox_")

    try:
        if lang == "python":
            result = _run_python(code, payload, temp_dir, image, timeout)
        elif lang == "java":
            result = _run_java(code, payload, temp_dir, image, timeout)
        elif lang in ["c++", "cpp"]:
            result = _run_cpp(code, payload, temp_dir, image, timeout)
        else:
            result = {
                "confirmed": False,
                "output":    "",
                "error":     f"Unsupported language: {language}",
                "exit_code": -1,
                "timed_out": False,
            }

        result["payload"]  = payload
        result["language"] = language
        return result

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ── PYTHON SANDBOX ────────────────────────────────────────────────────────────
def _run_python(code: str, payload: str, temp_dir: str, image: str, timeout: int) -> dict:
    code_file = os.path.join(temp_dir, "target.py")

    wrapped_code = f"""
import sys
import types

{code}

payload = {repr(payload)}

funcs = [
    obj for name, obj in list(globals().items())
    if isinstance(obj, types.FunctionType) and not name.startswith('_')
]

if funcs:
    target_func = funcs[0]
    try:
        import inspect
        sig        = inspect.signature(target_func)
        num_params = len(sig.parameters)

        if num_params == 0:
            result = target_func()
        elif num_params == 1:
            result = target_func(payload)
        elif num_params == 2:
            result = target_func(payload, payload)
        else:
            args   = [payload] * num_params
            result = target_func(*args)

        print(f"RESULT: {{result}}")
    except Exception as e:
        print(f"EXCEPTION: {{type(e).__name__}}: {{e}}")
else:
    print("NO_FUNCTIONS_FOUND")
"""

    with open(code_file, "w") as f:
        f.write(wrapped_code)

    run_cmd = (
        "pip install bcrypt flask requests sqlalchemy cryptography "
        "passlib pyjwt argon2-cffi werkzeug "
        "--root-user-action=ignore -q 2>/dev/null ; "
        "python /sandbox/target.py"
    )

    return _docker_run(
        image=image,
        temp_dir=temp_dir,
        command=["sh", "-c", run_cmd],
        timeout=60,
        network="bridge"
    )


# ── JAVA SANDBOX ──────────────────────────────────────────────────────────────
def _run_java(code: str, payload: str, temp_dir: str, image: str, timeout: int) -> dict:
    class_name = "Target"
    for line in code.split("\n"):
        if "public class" in line:
            parts = line.split("public class")
            if len(parts) > 1:
                class_name = parts[1].strip().split()[0].split("{")[0].strip()
                break

    java_safe_payload = _java_string(payload)

    if "public static void main" not in code:
        wrapped_code = f"""
import java.sql.*;
import java.security.*;
import java.util.*;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.nio.file.*;
import java.nio.charset.*;
import java.math.BigInteger;

{code}

class PayloadRunner {{
    public static void main(String[] args) {{
        String payload = "{java_safe_payload}";
        {class_name} target = new {class_name}();
        try {{
            java.lang.reflect.Method[] methods = target.getClass().getDeclaredMethods();
            if (methods.length > 0) {{
                java.lang.reflect.Method method = methods[0];
                method.setAccessible(true);
                int paramCount = method.getParameterCount();
                Object[] methodArgs = new Object[paramCount];
                for (int i = 0; i < paramCount; i++) {{
                    methodArgs[i] = payload;
                }}
                Object result = method.invoke(target, methodArgs);
                System.out.println("RESULT: " + result);
            }} else {{
                System.out.println("NO_METHODS_FOUND");
            }}
        }} catch (java.lang.reflect.InvocationTargetException e) {{
            System.out.println("EXCEPTION: " + e.getCause().getClass().getName()
                + ": " + e.getCause().getMessage());
        }} catch (Exception e) {{
            System.out.println("EXCEPTION: " + e.getClass().getName()
                + ": " + e.getMessage());
        }}
    }}
}}
"""
    else:
        wrapped_code = code

    code_file = os.path.join(temp_dir, f"{class_name}.java")
    with open(code_file, "w") as f:
        f.write(wrapped_code)

    compile_cmd = (
        f"cd /sandbox && "
        f"javac -nowarn -cp '.:/sandbox/lib/*' {class_name}.java 2>&1 && "
        f"java -cp '.:/sandbox/lib/*' PayloadRunner 2>&1"
    )

    return _docker_run(
        image=image,
        temp_dir=temp_dir,
        command=["bash", "-c", compile_cmd],
        timeout=120
    )


# ── C++ SANDBOX ───────────────────────────────────────────────────────────────
def _run_cpp(code: str, payload: str, temp_dir: str, image: str, timeout: int) -> dict:
    code_lines  = code.split("\n")
    clean_lines = []
    inside_main = False
    brace_count = 0

    for line in code_lines:
        if "int main(" in line or "int main (" in line:
            inside_main = True
            brace_count = 0
        if inside_main:
            brace_count += line.count("{") - line.count("}")
            if brace_count <= 0 and brace_count != 0:
                inside_main = False
            continue
        clean_lines.append(line)

    clean_code = "\n".join(clean_lines)
    cpp_safe_payload = _java_string(payload)

    wrapped_code = f"""
#include <iostream>
#include <string>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <map>
#include <memory>

{clean_code}

int main() {{
    std::string payload = "{cpp_safe_payload}";
    try {{
        #if defined(HAS_AUTH)
            auto result = authenticate(payload, payload);
            std::cout << "RESULT: " << result << std::endl;
        #elif defined(HAS_LOGIN)
            auto result = login(payload, payload);
            std::cout << "RESULT: " << result << std::endl;
        #elif defined(HAS_READ)
            auto result = readFile(payload);
            std::cout << "RESULT: " << result << std::endl;
        #elif defined(HAS_SEARCH)
            auto result = searchProducts(payload);
            std::cout << "RESULT: " << result << std::endl;
        #elif defined(HAS_EXECUTE)
            auto result = executeCommand(payload);
            std::cout << "RESULT: " << result << std::endl;
        #else
            std::cout << "PAYLOAD_INJECTED: " << payload << std::endl;
        #endif
    }} catch (const std::exception& e) {{
        std::cout << "EXCEPTION: " << e.what() << std::endl;
    }} catch (...) {{
        std::cout << "UNKNOWN_EXCEPTION" << std::endl;
    }}
    return 0;
}}
"""

    code_file = os.path.join(temp_dir, "target.cpp")
    with open(code_file, "w") as f:
        f.write(wrapped_code)

    compile_and_run = (
        "apt-get update -q > /dev/null 2>&1 ; "
        "apt-get install -y libssl-dev -q > /dev/null 2>&1 ; "
        "cd /sandbox && "
        "g++ -o target target.cpp "
        "-DHAS_AUTH -DHAS_LOGIN -DHAS_READ -DHAS_SEARCH -DHAS_EXECUTE "
        "-lssl -lcrypto -lstdc++ 2>/dev/null || "
        "g++ -o target target.cpp "
        "-DHAS_AUTH -DHAS_LOGIN -DHAS_READ -DHAS_SEARCH -DHAS_EXECUTE "
        "-lstdc++ 2>/dev/null && "
        "./target"
    )

    return _docker_run(
        image=image,
        temp_dir=temp_dir,
        command=["bash", "-c", compile_and_run],
        timeout=120
    )


# ── DOCKER RUNNER ─────────────────────────────────────────────────────────────
def _docker_run(
    image:    str,
    temp_dir: str,
    command:  list,
    timeout:  int,
    network:  str = "none"
) -> dict:

    os.chmod(temp_dir, 0o755)
    for f in os.listdir(temp_dir):
        os.chmod(os.path.join(temp_dir, f), 0o644)

    docker_cmd = [
        "docker", "run",
        "--rm",
        "--network", network,
        "--memory",  MEMORY_LIMIT,
        "--cpus",    CPU_LIMIT,
        "--tmpfs",   "/tmp:size=128m",
        "-v", f"{temp_dir}:/sandbox",
        image
    ] + command

    try:
        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output    = result.stdout.strip()
        error     = result.stderr.strip()
        exit_code = result.returncode

        has_exception = (
            "EXCEPTION"          in output or
            "NO_FUNCTIONS_FOUND" in output or
            "NO_METHODS_FOUND"   in output
        )

        # Confirmed only when:
        # 1. RESULT: True  — boolean function returned True (auth bypass, logic flaw)
        # 2. RESULT: <file contents> — file read returned real content (path traversal)
        # RESULT: False and RESULT: None are NOT confirmed
        auth_bypass = "RESULT: True" in output

        file_read_success = (
            "RESULT:" in output and
            "RESULT: False" not in output and
            "RESULT: None"  not in output and
            "RESULT: True"  not in output and
            len(output) > 30 and
            not has_exception
        )

        confirmed = (
            exit_code == 0 and
            not has_exception and
            (auth_bypass or file_read_success)
        )

        return {
            "confirmed": confirmed,
            "output":    output,
            "error":     error,
            "exit_code": exit_code,
            "timed_out": False,
        }

    except subprocess.TimeoutExpired:
        return {
            "confirmed": False,
            "output":    "",
            "error":     f"Container timed out after {timeout}s",
            "exit_code": -1,
            "timed_out": True,
        }
    except Exception as e:
        return {
            "confirmed": False,
            "output":    "",
            "error":     str(e),
            "exit_code": -1,
            "timed_out": False,
        }


# ── RUN ALL ATTACKS ───────────────────────────────────────────────────────────
def run_all_attacks(
    code:     str,
    attacks:  list,
    language: str
) -> list:
    results = []
    skip_phrases = ["n/a", "none", "", "not applicable", "no payload"]

    for i, attack in enumerate(attacks):
        payload = attack.get("payload", "")

        if not payload or payload.strip().lower() in skip_phrases or len(payload.strip()) < 3:
            attack["sandbox"] = {
                "confirmed": False,
                "output":    "No payload to test",
                "error":     "",
                "exit_code": 0,
                "timed_out": False,
                "skipped":   True
            }
            results.append(attack)
            continue

        print(f"  [SANDBOX] Testing attack {i+1}/{len(attacks)} "
              f"— {attack.get('cwe', 'Unknown')} — {language}...")

        timeout_val = 120 if language.lower() == "java" else 60

        sandbox_result = run_in_sandbox(
            code=code,
            payload=payload,
            language=language,
            timeout=timeout_val
        )

        attack["sandbox"] = sandbox_result

        status = (
            "CONFIRMED"     if sandbox_result["confirmed"] else
            "TIMEOUT"       if sandbox_result["timed_out"] else
            "NOT CONFIRMED"
        )

        print(f"  [SANDBOX] {attack.get('cwe', 'Unknown')} — {status}")
        if sandbox_result["output"]:
            print(f"  [SANDBOX] Output : {sandbox_result['output'][:100]}")
        if sandbox_result["error"] and not sandbox_result["confirmed"]:
            print(f"  [SANDBOX] Error  : {sandbox_result['error'][:100]}")

        results.append(attack)

    confirmed_count = sum(1 for a in results if a.get("sandbox", {}).get("confirmed"))
    print(f"  [SANDBOX] {confirmed_count}/{len(results)} attacks confirmed by execution")

    return results


# ── QUICK TEST ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("SANDBOX TEST — Python SQL Injection")
    print("=" * 60)

    test_code = """
def login(username, password):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    conn.execute("CREATE TABLE users (username TEXT, password TEXT)")
    conn.execute("INSERT INTO users VALUES ('admin', 'secret')")
    conn.commit()
    cursor = conn.execute(
        f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    )
    return cursor.fetchone() is not None
"""
    test_payload = "' OR '1'='1' --"
    print(f"Payload  : {test_payload}")
    result = run_in_sandbox(code=test_code, payload=test_payload, language="python")
    print(f"Confirmed : {result['confirmed']}")
    print(f"Output    : {result['output']}")

    print("\n" + "=" * 60)
    print("SANDBOX TEST — Java Path Traversal")
    print("=" * 60)

    java_code = """
import java.io.*;
import java.nio.file.*;

public class Target {
    public String readFile(String filename) throws Exception {
        Path path = Paths.get("/tmp/" + filename);
        return new String(Files.readAllBytes(path));
    }
}
"""
    java_payload = "../etc/passwd"
    print(f"Payload  : {java_payload}")
    java_result = run_in_sandbox(code=java_code, payload=java_payload, language="java")
    print(f"Confirmed : {java_result['confirmed']}")
    print(f"Output    : {java_result['output'][:100]}")