#!/usr/bin/env python3
"""Security validation and configuration setup for Spotify Insights."""

import sys

from core.config import SecureConfig


def main():
    """Main security validation and setup routine."""
    print("🔐 Spotify Insights - Security Configuration Validator")
    print("=" * 60)

    # Initialize config manager
    config = SecureConfig()

    # Run interactive setup if needed
    config.setup_interactive()

    print("\n" + "=" * 60)
    print("🔍 Configuration Validation")
    print("=" * 60)

    # Validate all configurations
    status = config.validate_all_configs()

    print("\n📊 Configuration Status:")
    print(f"{'Service':<15} {'Status':<12} {'Details'}")
    print("-" * 50)

    # Spotify status
    if status["spotify"]["configured"]:
        scopes = status["spotify"].get("scopes", [])
        print(f"{'Spotify':<15} {'✅ Ready':<12} {len(scopes)} scopes configured")
        if len(scopes) > 3:
            print(f"{'':>27} Full access enabled")
    else:
        error = status["spotify"]["error"]
        print(f"{'Spotify':<15} {'❌ Error':<12} {error}")

    # Last.fm status
    if status["lastfm"]["configured"]:
        print(f"{'Last.fm':<15} {'✅ Ready':<12} Global trends available")
    else:
        error = status["lastfm"]["error"]
        if "not configured" in error:
            print(f"{'Last.fm':<15} {'⚠️  Optional':<12} {error}")
        else:
            print(f"{'Last.fm':<15} {'❌ Error':<12} {error}")

    # AudioDB status
    if status["audiodb"]["configured"]:
        tier = status["audiodb"].get("tier", "unknown")
        print(f"{'AudioDB':<15} {'✅ Ready':<12} {tier.title()} tier access")
    else:
        error = status["audiodb"]["error"]
        print(f"{'AudioDB':<15} {'❌ Error':<12} {error}")

    print("\n" + "=" * 60)
    print("🛡️  Security Checklist")
    print("=" * 60)

    # Security checklist
    env_file = config.env_file
    security_checks = []

    # Check .env file exists
    if env_file.exists():
        security_checks.append(("✅", ".env file exists"))

        # Check file permissions (Unix-like systems)
        if hasattr(env_file, "stat") and not sys.platform.startswith("win"):
            file_mode = oct(env_file.stat().st_mode)[-3:]
            if file_mode == "600":
                security_checks.append(("✅", "File permissions are secure (600)"))
            else:
                security_checks.append(
                    ("⚠️", f"File permissions too open ({file_mode}) - consider chmod 600")
                )
        else:
            security_checks.append(("ℹ️", "File permissions check skipped (Windows)"))
    else:
        security_checks.append(("❌", ".env file missing"))

    # Check .gitignore
    gitignore_file = config.project_root / ".gitignore"
    if gitignore_file.exists():
        gitignore_content = gitignore_file.read_text(encoding="utf-8")
        if ".env" in gitignore_content:
            security_checks.append(("✅", ".env files excluded from git"))
        else:
            security_checks.append(("⚠️", ".env not in .gitignore - credentials may be exposed"))
    else:
        security_checks.append(("⚠️", ".gitignore missing"))

    # Check for credential files in current directory
    credential_patterns = ["env_data", "*_keys", "*_secrets", "credentials.*"]
    found_credentials = []
    for pattern in credential_patterns:
        if pattern.startswith("*"):
            # Use glob for wildcard patterns
            from glob import glob

            matches = glob(pattern)
            found_credentials.extend(matches)
        else:
            # Direct file check
            file_path = config.project_root / pattern
            if file_path.exists():
                found_credentials.append(pattern)

    if found_credentials:
        security_checks.append(
            ("⚠️", f"Found potential credential files: {', '.join(found_credentials)}")
        )
    else:
        security_checks.append(("✅", "No exposed credential files found"))

    for icon, message in security_checks:
        print(f"{icon} {message}")

    print("\n" + "=" * 60)
    print("🚀 Next Steps")
    print("=" * 60)

    if status["spotify"]["configured"]:
        print("✅ Ready to run Spotify analysis!")
        print("   Try: python -m src.main")

        if status["lastfm"]["configured"]:
            print("✅ Ready for global trend comparison!")
            print("   Try: python -m src.lastfm_main")
        else:
            print("💡 Optional: Configure Last.fm for global trend analysis")
    else:
        print("🔧 Configuration needed:")
        print("   1. Add your Spotify API credentials to .env")
        print("   2. Get credentials from: https://developer.spotify.com/dashboard")
        print("   3. Re-run this script to validate")

    print("\n📚 Security Best Practices:")
    print("   • Never commit .env files to version control")
    print("   • Regenerate API keys if they are ever exposed")
    print("   • Use restrictive file permissions (chmod 600) on Unix systems")
    print("   • Regularly audit your .gitignore file")

    # Return exit code based on Spotify config (required)
    return 0 if status["spotify"]["configured"] else 1


if __name__ == "__main__":
    sys.exit(main())
