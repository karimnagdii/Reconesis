
import argparse
import logging
from src.core.reconesis import ReconesisEngine

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("reconesis.log"),
            logging.StreamHandler()
        ]
    )

def main():
    setup_logging()
    parser = argparse.ArgumentParser(description="Reconesis: AI-Driven Network Reconnaissance Agent")
    parser.add_argument("--target", required=True, help="Target IP address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)")
    args = parser.parse_args()

    try:
        engine = ReconesisEngine()
        engine.start_scan(args.target)
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=True)

if __name__ == "__main__":
    main()
