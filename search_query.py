from splunklib import client, results
from .utils import Utils
from config import DefaultConfig
import os, json
import requests,logging

utils = Utils()
CONFIG = DefaultConfig()
#logging.basicConfig(level=logging.INFO,format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) 
class SearchQuery():
    
    def __init__(self):
        self._splunk_host = CONFIG.SPLUNK_HOST
        self._splunk_port = CONFIG.SPLUNK_PORT
        self._splunk_token = CONFIG.SPLUNK_TOKEN
        self._splunk_log_uri = CONFIG.SPLUNK_LOGS_INJECT_URL
        self._splunk_log_inject_token = CONFIG.SPLUNK_LOGS_INJECT_TOKEN

    def get_splunk_service(self):
        service = client.connect(
            host=self._splunk_host,
            port=self._splunk_port,
            splunkToken=self._splunk_token
        )
        return service
    
    def get_result(self, time, search_query):
        #service = self.get_splunk_service()
        service = client.connect(
            host=self._splunk_host,
            port=self._splunk_port,
            splunkToken=self._splunk_token,
            app="tapestry"
        )
        if time == 'custom':
            earlist_time = ''
            latest_time = 'now'
        else:
            earlist_time = time
            latest_time = 'now'
        kwargs_oneshot = {
            "earliest_time": earlist_time,
            "latest_time": latest_time,
            "output_mode": 'json',
            "count":"10"
        }
        logger.info("earlist_time : {}".format(earlist_time))
        logger.info("latest_time : {}".format(latest_time))
        logger.info("splunk_query : {}".format(search_query))
        oneshotsearch_results = service.jobs.oneshot(search_query, **kwargs_oneshot)
        result1=  results.JSONResultsReader(oneshotsearch_results)
        #print("Splunk Results",result1)
        
        return result1
    
    def get_result_sfcc(self, time, search_query):
        service = client.connect(
            host=self._splunk_host,
            port=self._splunk_port,
            splunkToken=self._splunk_token,
            app="tapestry"
        )
        if time == 'custom':
            earlist_time = ''
            latest_time = 'now'
        else:
            earlist_time = time
            latest_time = 'now'
        kwargs_oneshot = {
            "earliest_time": earlist_time,
            "latest_time": latest_time,
            "output_mode": 'json',
            "count":"10"
        }
        print("time===",time)
        logger.info("earlist_time : {}".format(earlist_time))
        logger.info("latest_time : {}".format(latest_time))
        logger.info("splunk_query : {}".format(search_query))
        oneshotsearch_results = service.jobs.oneshot(search_query, **kwargs_oneshot)
        result1=  results.JSONResultsReader(oneshotsearch_results)
        
        return result1
    
    def pushLogsToSplunkIndex(self,payload):
       
        url = self._splunk_log_uri
        logging.info("url : {}".format(url))
        headers = {"Content-Type": "application/json", "Accept": "application/json","Authorization": self._splunk_log_inject_token}
        logging.info("Splunk Token : {}".format(self._splunk_log_inject_token))
        response = requests.request("POST", url, headers=headers, data=payload)
        logging.info(response.text)
        if response.status_code == 200:
            logging.info("Status: {} , Headers: {} , Error Response: {} ".format(response.status_code,response.headers,response.json()))
            



        
    
