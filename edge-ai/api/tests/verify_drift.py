"""Run the intercepted real Evaluation workflow with drift-specific fixtures."""

from verify_evaluation import run

if __name__ == "__main__":
    run(drift=True)
