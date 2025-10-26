from shodan import Shodan
from censys.search import CensysHosts
import os
from dotenv import load_dotenv
import inquirer

# Load environment variables from .env file
load_dotenv('.env_file') 

# Unified query configuration for both Shodan and Censys
SCAN_CONFIG = {
    "scope": {
        "shodan": 'org:"Acme Corp"',  # or net:x.x.x.x/yy or asn:ASXXX
        "censys": 'autonomous_system.organization: "Acme Corp"'  # or ip:x.x.x.x/yy
    },
    "services": {
        "databases": {
            "elasticsearch": {
                "port": 9200,
                "shodan_query": "port:9200 product:elastic",
                "censys_query": "services.port: 9200 AND services.service_name: HTTP",
                "risk": "high",
                "description": "Exposed Elasticsearch cluster"
            },
            "mongodb": {
                "port": 27017,
                "shodan_query": "port:27017 product:mongodb",
                "censys_query": "services.port: 27017",
                "risk": "critical",
                "description": "Unauthenticated MongoDB instance"
            },
            "redis": {
                "port": 6379,
                "shodan_query": "port:6379 product:redis",
                "censys_query": "services.port: 6379",
                "risk": "high",
                "description": "Redis key-value store"
            },
            "mysql": {
                "port": 3306,
                "shodan_query": "port:3306 product:mysql",
                "censys_query": "services.port: 3306",
                "risk": "high",
                "description": "MySQL database server"
            },
            "postgresql": {
                "port": 5432,
                "shodan_query": "port:5432 product:postgresql",
                "censys_query": "services.port: 5432",
                "risk": "high",
                "description": "PostgreSQL database server"
            },
            "mssql": {
                "port": 1433,
                "shodan_query": "port:1433 product:\"microsoft sql\"",
                "censys_query": "services.port: 1433",
                "risk": "high",
                "description": "Microsoft SQL Server"
            },
            "cassandra": {
                "port": 9042,
                "shodan_query": "port:9042 product:cassandra",
                "censys_query": "services.port: 9042",
                "risk": "high",
                "description": "Apache Cassandra cluster"
            }
        },
        "file_servers": {
            "ftp": {
                "port": 21,
                "shodan_query": "port:21 product:ftp",
                "censys_query": "services.port: 21 AND services.service_name: FTP",
                "risk": "medium",
                "description": "FTP file server"
            },
            "smb": {
                "port": 445,
                "shodan_query": "port:445",
                "censys_query": "services.port: 445",
                "risk": "high",
                "description": "SMB/CIFS file share"
            },
            "nfs": {
                "port": 2049,
                "shodan_query": "port:2049 product:nfs",
                "censys_query": "services.port: 2049",
                "risk": "medium",
                "description": "Network File System"
            },
            "rsync": {
                "port": 873,
                "shodan_query": "port:873 product:rsync",
                "censys_query": "services.port: 873",
                "risk": "medium",
                "description": "Rsync file synchronization"
            }
        }
    }
}

# --- API Keys ---
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY") or "YOUR_SHODAN_API_KEY_HERE"
CENSYS_API_ID = os.getenv("CENSYS_API_ID") or "YOUR_CENSYS_API_ID_HERE"
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET") or "YOUR_CENSYS_SECRET_KEY_HERE"

def initialise_scanners():
    """
    Initialises and returns the Shodan and Censys API clients.
    Handles basic error checking for API keys.
    """
    shodan_api = None
    censys_h = None

    # Initialize Shodan API
    try:
        if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY_HERE":
            print("❌ SHODAN_API_KEY is not set")
        else:
            shodan_api = Shodan(SHODAN_API_KEY)
            shodan_api.info()
            print(f"✅ Shodan API is working. Key starts with: {SHODAN_API_KEY[:4]}...")
    except Shodan.APIError as e:
        print(f"❌ Shodan API Error: {e}. Check your key.")
        shodan_api = None
    except Exception as e:
        print(f"❌ An unexpected error occurred with Shodan: {e}")
        shodan_api = None

    # Initialize Censys API
    try:
        if CENSYS_API_SECRET == "YOUR_CENSYS_SECRET_KEY_HERE":
            print("❌ CENSYS_API_SECRET is not set")
        else:
            censys_h = CensysHosts(CENSYS_API_ID, CENSYS_API_SECRET)
            print(f"✅ Censys API is working. Key starts with: {CENSYS_API_SECRET[:4]}...")
    except Exception as e:
        print(f"❌ An unexpected error occurred with Censys: {e}")
        censys_h = None

    return shodan_api, censys_h

def api_usage(shodan_api, censys_h):
    """
    Displays API usage information for Shodan and Censys.
    """
    print("API Usage:")
    if shodan_api:
        try:
            info = shodan_api.info()
            print(f"Shodan: {info}")
        except Exception as e:
            print(f"Shodan: Error getting info - {e}")
    else:
        print("Shodan: Not initialized")
    
    if censys_h:
        try:
            # Note: Censys account_info() might require different method
            print("Censys: API initialized")
        except Exception as e:
            print(f"Censys: Error getting info - {e}")
    else:
        print("Censys: Not initialized")

def test_inquirer():
    """Test the inquirer library"""
    questions = [
        inquirer.Text('name', message="What is your name?"),
        inquirer.Text('email', message="What is your email?"),
        inquirer.Text('age', message="What is your age?"),
    ]
    answers = inquirer.prompt(questions)
    print(answers)

if __name__ == "__main__":
    # # Initialize API clients
    # shodan_api, censys_h = initialize_scanners()
    
    # # Display API usage information
    # api_usage(shodan_api, censys_h)
    
    # --- Test the inquirer library ---
    test_inquirer()
