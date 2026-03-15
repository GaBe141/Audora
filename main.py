#!/usr/bin/env python3
"""
Audora - Enhanced Music Discovery System - Main Entry Point
==========================================================

Enhanced music discovery system with ML-powered viral prediction,
multi-platform social media monitoring, and real-time analytics.

Usage:
    python main.py --help                    # Show help
    python main.py --mode single             # Run single discovery cycle
    python main.py --mode continuous         # Run continuous monitoring
    python main.py --setup                   # Run system setup
    python main.py --demo                    # Run demonstration

Features:
    🎵 Multi-platform social media discovery (TikTok, YouTube, Instagram, Twitter)
    🧠 ML-powered viral prediction with 80%+ accuracy
    📊 Real-time trend analysis and cross-platform correlation
    🔔 Multi-channel notifications (Email, Slack, Discord, Webhook)
    💾 Enterprise-grade data persistence with automatic backups
    🛡️ Resilient API integration with circuit breakers and retry logic
"""

import argparse
import sys
from pathlib import Path

# Add directories to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.extend(
    [
        str(PROJECT_ROOT / "core"),
        str(PROJECT_ROOT / "integrations"),
        str(PROJECT_ROOT / "analytics"),
        str(PROJECT_ROOT / "visualization"),
    ]
)


def main():
    """Main entry point for Audora - AI-Powered Music Discovery System."""
    parser = argparse.ArgumentParser(
        description="🎵 Audora - AI-Powered Music Discovery System with ML Analytics",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main.py --setup                   # Initial system setup
    python main.py --mode single             # Single discovery cycle
    python main.py --mode continuous -i 15   # Monitor every 15 minutes
    python main.py --demo statistical        # Statistical analysis demo
    python main.py --demo trending           # Trending analysis demo

For detailed documentation, see docs/QUICK_START.md
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["single", "continuous"],
        help="Run mode: single discovery cycle or continuous monitoring",
    )

    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=15,
        help="Monitoring interval in minutes (for continuous mode, default: 15)",
    )

    parser.add_argument(
        "--setup", action="store_true", help="Run comprehensive system setup and configuration"
    )

    parser.add_argument(
        "--demo",
        choices=["statistical", "trending", "multi_source", "platform", "all"],
        help="Run demonstration scripts",
    )

    parser.add_argument(
        "--validate", action="store_true", help="Validate system configuration and security"
    )

    args = parser.parse_args()

    # Handle setup
    if args.setup:
        print("🚀 Running Audora Music Discovery System Setup...")
        try:
            from scripts.setup import main as setup_main

            return setup_main()
        except ImportError:
            print("❌ Setup script not found. Please ensure scripts/setup.py exists.")
            return 1

    # Handle validation
    if args.validate:
        print("🔍 Validating system configuration...")
        try:
            from scripts.validate_security import main as validate_main

            return validate_main()
        except ImportError:
            print("❌ Validation script not found.")
            return 1

    # Handle demos
    if args.demo:
        print(f"🎮 Running {args.demo} demonstration...")
        demo_map = {
            "statistical": "scripts.demo_statistical_analysis",
            "trending": "scripts.demo_trending_analysis",
            "multi_source": "scripts.demo_multi_source",
            "platform": "scripts.complete_platform_demo",
        }

        if args.demo == "all":
            for demo_name, demo_module in demo_map.items():
                print(f"\n🎯 Running {demo_name} demo...")
                try:
                    module = __import__(demo_module, fromlist=["main"])
                    module.main()
                except ImportError as e:
                    print(f"❌ Demo {demo_name} not found: {e}")
                except Exception as e:
                    print(f"⚠️ Demo {demo_name} error: {e}")
        else:
            try:
                module = __import__(demo_map[args.demo], fromlist=["main"])
                return module.main()
            except ImportError:
                print(f"❌ Demo {args.demo} not found.")
                return 1
        return 0

    # Handle discovery modes
    if args.mode:
        print("🎵 Enhanced Music Discovery System v2.0")
        print("=" * 50)

        try:
            if args.mode == "single":
                print("🚀 Running single discovery cycle...")
                from core.discovery_app import main as discovery_main

                return discovery_main()

            elif args.mode == "continuous":
                print(f"🔄 Starting continuous monitoring (every {args.interval} minutes)")
                print("Press Ctrl+C to stop...")
                from core.discovery_app import main as discovery_main

                sys.argv = [
                    "discovery_app.py",
                    "--mode",
                    "continuous",
                    "--interval",
                    str(args.interval),
                ]
                return discovery_main()

        except ImportError as e:
            print(f"❌ Discovery app not found: {e}")
            print("💡 Run 'python main.py --setup' first to set up the system")
            return 1
        except Exception as e:
            print(f"❌ Discovery error: {e}")
            return 1

    # No arguments provided - show help and interactive menu
    if len(sys.argv) == 1:
        print("\n🎵 Welcome to Audora - AI-Powered Music Discovery System v2.0!")
        print("=" * 60)
        print("\n🚀 Features:")
        print("  • Multi-platform social media discovery (TikTok, YouTube, Instagram)")
        print("  • ML-powered viral prediction with 80%+ accuracy")
        print("  • Real-time trend analysis and correlation detection")
        print("  • Multi-channel notifications (Email, Slack, Discord)")
        print("  • Enterprise-grade data persistence and backups")
        print("  • Resilient API integration with circuit breakers")

        print("\n📋 Quick Start:")
        print("  1. python main.py --setup           # Set up the system")
        print("  2. python main.py --mode single     # Run discovery")
        print("  3. python main.py --demo all        # See demonstrations")

        print("\n📖 For detailed help:")
        print("  python main.py --help")
        print("  See docs/QUICK_START.md for complete guide")

        return 0

    # Show help if no valid arguments
    parser.print_help()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
