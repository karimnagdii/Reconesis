
import argparse
import logging
import sys
from src.core.reconesis import ReconesisEngine
from src.utils.config import validate_config

def setup_logging(verbose=False):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("reconesis.log"),
            logging.StreamHandler()
        ]
    )

def validate_target(target: str) -> bool:
    """Validates that target is a valid IP or CIDR range."""
    import ipaddress
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        logging.error(f"Invalid target: '{target}'. Must be a valid IP address or CIDR range (e.g., 192.168.1.0/24)")
        return False

def main():
    parser = argparse.ArgumentParser(description="Reconesis: AI-Driven Network Reconnaissance Agent")
    parser.add_argument("--target", "-t", required=True, help="Target IP address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output for debugging")
    args = parser.parse_args()

    setup_logging(verbose=args.verbose)
    logger = logging.getLogger("Main")

    # Pre-flight checks before scanning starts
    logger.info("═" * 60)
    logger.info("🔍 Reconesis Pre-flight Validation")
    logger.info("═" * 60)

    # 1. Validate target
    if not validate_target(args.target):
        logger.error("Target validation failed. Aborting.")
        sys.exit(1)
    logger.info(f"✓ Target validation passed: {args.target}")

    # 2. Validate Groq API configuration
    is_valid, error_msg = validate_config()
    if not is_valid:
        logger.error(error_msg)
        sys.exit(1)
    logger.info("✓ Groq API configuration validated")

    # 3. Check nmap is available (lazy check in executor, but log here too)
    logger.info("Nmap availability will be checked during execution")

    logger.info("═" * 60)
    logger.info("✅ All pre-flight checks passed. Starting scan...")
    logger.info("═" * 60)

    try:
        engine = ReconesisEngine()
        engine.start_scan(args.target)
    except KeyboardInterrupt:
        logger.info("\n⏹️ Scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
