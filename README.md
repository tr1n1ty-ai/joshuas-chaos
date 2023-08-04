# Joshua's Chaos: Security Chaos Engineering Tool

## Overview

Joshua's Chaos is a Python-based security chaos engineering tool inspired by the 1980s movie "WarGames". The tool simulates security chaos experiments that assess the security postures of AWS environments, particularly the integrity of S3 buckets. It's a work-in-progress, currently in a beta phase, and contributions are welcome.

As an homage to the movie, Joshua's Chaos prints messages slowly to the console, building suspense while preparing and running security chaos experiments.

The tool is designed to be as user-friendly as possible. To use it, simply run the main script and follow the interactive console prompts.

## Prerequisites

- Python 3.7 or higher
- Boto3 Python Library
- AWS account with access to S3 services
- AWS credentials configured on your local machine

## Experiments

Joshua's Chaos includes experiments to:

1. **Test S3 bucket versioning:** The tool first disables versioning for randomly selected S3 buckets, then checks if it can be re-enabled. The goal of this test is to identify how long it takes to discover and remediate such changes, simulating an attacker attempting to sabotage data recovery options.

Please note that these experiments can disrupt AWS services, so they should be run in a testing or staging environment, never in production.

## Usage

1. Install the required dependencies:
   ```
   pip install boto3 curses colorama
   ```

2. Clone the repository:
   ```
   git clone https://github.com/user/joshuas-chaos.git
   ```

3. Navigate to the cloned directory:
   ```
   cd joshuas-chaos
   ```

4. Run the script:
   ```
   python main.py
   ```

5. Follow the on-screen prompts to execute an experiment.

## Contribution

This project is in its early stages, and we'd love to see your contributions! You can contribute in many ways:

- **Bug Reports:** Found a problem? Let us know.
- **Feature Requests:** Have an idea for a new experiment? We'd love to hear it.
- **Pull Requests:** Got something you want to add or change? Please feel free to fork, change, and submit a pull request.

## Note

Joshua's Chaos is intended for legal security testing and educational purposes only. Any misuse of this software will not be the responsibility of the author. Use it responsibly.
