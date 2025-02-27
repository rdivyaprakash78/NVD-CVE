from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

uri = "mongodb+srv://dprakashdprakash32:Ramayanam1!@nvd-cve.17zcq.mongodb.net/?retryWrites=true&w=majority&appName=NVD-CVE"
client = MongoClient(uri, server_api=ServerApi('1'))

db = client.vulnerabilities

cves = db["cve_info"]
