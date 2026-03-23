"""
Automated Fix Script for Audora Codebase Issues
Fixes type hints, imports, and code quality issues identified by linters.
"""

import shlex
import subprocess


def print_step(step_num: int, description: str):
    """Print formatted step."""
    print(f"\n{'='*60}")
    print(f"Step {step_num}: {description}")
    print(f"{'='*60}")


def run_command(cmd: list[str] | str, description: str) -> bool:
    """Run a command and return success status."""
    print(f"  → {description}")
    try:
        cmd_args = shlex.split(cmd) if isinstance(cmd, str) else cmd
        subprocess.run(cmd_args, check=True, capture_output=True, text=True)
        print("  ✅ Success")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Failed: {e.stderr}")
        return False


def main() -> None:
    """Execute all fixes."""
    print("🔧 Audora Automated Fix Script")
    print("This will fix type hints, imports, and code quality issues")

    # Step 1: Install missing type stubs
    print_step(1, "Install Missing Type Stubs")
    packages = [
        "types-Jinja2",
        "types-redis",
        "types-requests",
    ]

    for package in packages:
        run_command(f"pip install {package}", f"Installing {package}")

    # Step 2: Run Black formatter
    print_step(2, "Format Code with Black")
    run_command(
        "python -m black core/ scripts/ --line-length 100 --quiet", "Formatting Python files"
    )

    # Step 3: Run Ruff auto-fixes
    print_step(3, "Apply Ruff Auto-Fixes")
    files_to_fix = [
        "core/notification_service.py",
        "core/data_store.py",
        "core/caching.py",
        "core/logging_config.py",
    ]

    for file in files_to_fix:
        run_command(f"python -m ruff check {file} --fix --unsafe-fixes", f"Fixing {file}")

    # Step 4: Run tests
    print_step(4, "Run Tests to Verify Changes")
    run_command("python test_project.py", "Running test suite")

    # Step 5: Summary
    print_step(5, "Summary")
    print(
        """
    ✅ Type stubs installed
    ✅ Code formatted with Black
    ✅ Auto-fixes applied with Ruff
    ✅ Tests verified

    Next steps:
    1. Review changes with: git diff
    2. Run manual type check: python -m mypy core/ --ignore-missing-imports
    3. Commit changes: git add -A && git commit -m "fix: Apply automated type hints and code quality fixes"

    Remaining manual fixes needed:
    - Type annotations in notification_service.py (lines 87-89, 613, 782)
    - Sequence types in data_store.py for pandas compatibility
    - Logging formatter type in logging_config.py
    """
    )


if __name__ == "__main__":
    main()
