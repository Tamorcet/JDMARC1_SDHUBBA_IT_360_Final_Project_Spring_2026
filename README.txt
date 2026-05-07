AI Hash Monitor - Fixed Version

Purpose:
This program monitors network packets with Scapy. When a packet payload or TCP stream buffer matches a SHA-256 hash from malicious_hashes.txt, it prints the alert and recommends remediation steps.

Files:
- main.py: Starts the program and prints alerts/recommendations.
- monitor.py: Captures packets and checks hashes.
- hash_db.py: Loads SHA-256 hashes from malicious_hashes.txt.
- ai_recommendations.py: Gives rule-based recommendations or optional OpenAI recommendations.
- config.py: Main settings.
- malicious_hashes.txt: Your malicious hash list.
- requirements.txt: Python packages.

Basic offline mode:
1. sudo apt update
2. sudo apt install python3 python3-pip -y
3. pip3 install -r requirements.txt
4. sudo python3 main.py

OpenAI mode:
1. Edit config.py and set USE_OPENAI_AI = True
2. Set your API key:
   export OPENAI_API_KEY="your_api_key_here"
3. Run:
   sudo -E python3 main.py

The -E keeps your OPENAI_API_KEY environment variable when using sudo.
