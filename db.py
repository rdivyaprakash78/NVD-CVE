from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import os
from dotenv import load_dotenv

load_dotenv()

username = str(os.environ.get('db_username'))
password = str(os.environ.get('db_password'))

uri = f"mongodb+srv://{username}:{password}@nvd-cve.17zcq.mongodb.net/?retryWrites=true&w=majority&appName=NVD-CVE"
client = MongoClient(uri, server_api=ServerApi('1'))

db = client.vulnerabilities

cves = db["cve_info"]


