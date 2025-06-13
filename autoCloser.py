import datetime
import os
import json, time
import pandas as pd
import matplotlib, logging
#import matplotlib.pylab as plt

import PortalServices.services as services
from PortalServices.search_query import SearchQuery
from PortalServices.graph_creator import create_graph, create_data_URI

from typing import List
#from PortalServices.splunk_operations import SplunkOperations
from PortalServices.utils import Utils
from PortalServices.serviceNow import ServiceNowOperations
from config import DefaultConfig


utils = Utils()
#splunk = SplunkOperations()
sq = SearchQuery()
sericenow = ServiceNowOperations()
CONFIG = DefaultConfig()

summaryPoints = []
resultResponse = []
dataPoints = {}
splunkLog = []
earlist_time = '-1h'
latest_time = 'now'

logger = logging.getLogger(__name__)

class AutoCloserOperations(): 

    def autoCloserIncidents(self,call_type,alert_name,sysId,incident,short_description) :
        search_array = utils.getSplunkQueryForAutoCloser(alert_name)
        logging.info("Data from Sheet : {}".format(search_array))
        path = utils.getRequestPath(call_type)
        search_value = ''
        title = 'Please find the SRE Ops Bot Analysis'
        fileName = 'SRE_Ops_Bot_Analysis'
        result = {}
        is_graph_search = 'search'
        result = {'Issues Overview': [], 'Analysis Details': []}
        result['Issues Overview'] = result['Issues Overview']+['Issue Name']
        result['Analysis Details'] = result['Analysis Details']+[short_description]
        result['Issues Overview'] = result['Issues Overview']+['Impacted Sites']
        result['Analysis Details'] = result['Analysis Details']+[call_type]
        for row in range(len(search_array))  :
            #print("Row data==========",search_array.iloc[row])
            if str(search_array.iloc[row]['timeperiod']) == '-15.0' or str(search_array.iloc[row]['timeperiod']) == '-15' :
                timeperiod ='-15m'
                span_value = '1m'
                earlist_time = timeperiod
            elif str(search_array.iloc[row]['timeperiod']) == '-30.0' or str(search_array.iloc[row]['timeperiod']) == '-30' :
                timeperiod ='-30m'
                span_value = '5m'
                earlist_time = timeperiod
            elif str(search_array.iloc[row]['timeperiod']) == '-60.0' or str(search_array.iloc[row]['timeperiod']) == '-60':
                timeperiod ='-1h'
                span_value = '5m'
                earlist_time = timeperiod
            elif str(search_array.iloc[row]['timeperiod']) == '-4.0' or str(search_array.iloc[row]['timeperiod']) == '-4' :
                timeperiod ='-4h'
                span_value = '15m'
                earlist_time = timeperiod
            elif str(search_array.iloc[row]['timeperiod']) == '-24.0' or str(search_array.iloc[row]['timeperiod']) == '-24' :
                timeperiod ='-24h'
                span_value = '15m'
                earlist_time = timeperiod
            trendName = search_array.iloc[row]['trends']
            logger.info("earlist_time : {}".format(timeperiod))
            logger.info("span_value : {}".format(span_value))
            print("search_array.iloc[0]['trends']", trendName)
            host_map = search_array.iloc[row]['host_mapping']
            host = path[host_map].values[0]

            if pd.isnull(search_array.iloc[row]['graph_query']) :
                is_graph_search = 'search'
                search_value = search_array.iloc[row]['search_query']
            else :
                is_graph_search = 'graph'
                search_value = search_array.iloc[row]['graph_query']
            try :
                search_q = str(search_value).replace("{request_host}",host)
            except Exception as e:
                logger.exception("Due to some issues with query not able to get the data from splunk: {} , error trace - {}".format(trendName,e))
                continue

            try :
                splukResult = sq.get_result_sfcc(timeperiod,search_q.replace('\n', ''))
            except Exception as e:
                logger.exception("Exception occurred while connecting to splunk : %s", str(e))

            data = []
            if not splukResult :
                logger.info("Splunk result is empty ")
            else :
                for item in splukResult:
                    logger.info("INFO : {}".format(item))
                    
                    if 'INFO' in str(item) :
                        logger.info("INFO : {}".format(item))
                        continue
                    data.append(item)
            if len(data)==0:
                continue
            if trendName == 'Trend_Query' : 
                if (len(data) > 0):
                    # Define spike detection parameters
                    spike_threshold = 0  # Threshold to determine a spike
                    # Initialize variables
                    in_spike = False
                    spike_start_time = None
                    spike_end_time = None
                    spikes = []
                    spikeData = []
                    # Iterate through the data
                    #for i, (time_str, value) in enumerate(data):
                    for dataRest in data :
                        current_time = self.parse_time(dataRest['_time'])
                        
                        if int(dataRest['Trend_5XX']) > spike_threshold:
                            if not in_spike:
                                # Spike started
                                in_spike = True
                                spike_start_time = current_time
                            # Update end time while still in spike
                            spike_end_time = current_time
                        else:
                            if in_spike:
                                # Spike ended
                                in_spike = False
                                spikes.append((spike_start_time, spike_end_time))
                                spike_start_time = None
                                spike_end_time = None
                    # Check if there was an ongoing spike till the end of data
                    if in_spike:
                        spikes.append((spike_start_time, spike_end_time))

                    # Output the results
                    if spikes:
                        for i, (start, end) in enumerate(spikes, start=1):
                            print(f"Spike {i}: Start Time: {start}, End Time: {end}")
                            spikeData.append("Spike "+str(i)+": Started at : "+str(start)+", Subsided at : "+str(end))
                    else:
                        spikeData.append("No spikes detected.")
                result['Issues Overview'] = result['Issues Overview']+["Observations"]
                result['Analysis Details'] = result['Analysis Details']+[spikeData]
                continue

            resdict = services.getDynamicFieldsResult(data)
            for key, value in resdict.items():
                result['Issues Overview'] = result['Issues Overview']+[key]
                result['Analysis Details'] = result['Analysis Details']+[value]
            logger.info("data length is: {}".format(len(data)))
            logger.info("data  is: {}".format(data))
            logger.info("data  in Result dict : {}".format(result))
            if trendName == 'Top_clientIps' :
                if pd.isnull(search_array.iloc[row]['dependent_query1']) :
                    logger.info("No Dependency query")
                else :
                    #result = self.dependentQueryData(timeperiod,search_array.iloc[row]['depedent_query'],host)
                    search_value = search_array.iloc[row]['dependent_query1']
                    ipslistdt = ''
                    n=0
                    for dataRest in data :
                        if n==0 :
                            ipslistdt = dataRest["Impacted_Client_IPs"]
                        else :
                            ipslistdt = ipslistdt+","+dataRest["Impacted_Client_IPs"]
                        n=n+1
                    logger.info("IPs List : {}".format(ipslistdt))
                    try :
                        search_value = str(search_value).replace("{request_host}",host)
                        search_q = str(search_value).replace("{client_ips}",ipslistdt)
                    except Exception as e:
                        logger.exception("Due to some issues with query not able to get the data from splunk: {} , error trace - {}".format(trendName,e))
                        continue

                    try :
                        splukResult = sq.get_result_sfcc(timeperiod,search_q.replace('\n', ''))
                    except Exception as e:
                        logger.exception("Exception occurred while connecting to splunk : %s", str(e))
                    data = []
                    vendordata = []
                    nonvendordata = []
                    if not splukResult :
                        logger.info("Splunk result is empty ")
                    else :
                        for item in splukResult:
                            logger.info("INFO : {}".format(item))
                            
                            if 'INFO' in str(item) :
                                logger.info("INFO : {}".format(item))
                                continue
                            data.append(item)
                    #data = self.dependentQueryData(timeperiod,search_array.iloc[row]['depedent_query'])
                    for dataRest in data :
                        logger.info("dataRest['vendor_traffic'] : {}".format(dataRest['vendor_traffic']))
                        logger.info("dataRest['Client_IP'] : {}".format(dataRest['Client_IP']))
                        if dataRest['vendor_traffic'] == "true" :
                            vendordata.append(dataRest['Client_IP'])
                        else :
                            nonvendordata.append(dataRest['Client_IP'])
                    '''result['Issues Overview'] = result['Issues Overview']+["Conclusion(Optional)"]
                    if len(vendordata) > 0 and len(nonvendordata) > 0 :
                        result['Analysis Details'] = result['Analysis Details']+[str(nonvendordata)+" : These Ips are part of Vendor Ip, no need to take any action, "+str(vendordata)+" : These Ips are not part of Vendor Ip"]
                    elif len(vendordata) > 0 and len(nonvendordata) == 0 :
                        result['Analysis Details'] = result['Analysis Details']+[str(vendordata)+" : These Ips are part of Vendor Ip List, no need to take any action "]
                    elif len(vendordata) == 0 and len(nonvendordata) > 0 :
                        result['Analysis Details'] = result['Analysis Details']+[str(nonvendordata)+" : These Ips are not part of Vendor Ip List"]'''
                    summary_details = ''
                    if pd.isnull(search_array.iloc[row]['dependent_query2']) :
                        logger.info("No Dependency query")
                        result['Issues Overview'] = result['Issues Overview']+["Conclusion(Optional)"]
                        if len(vendordata) > 0 and len(nonvendordata) > 0 :
                            result['Analysis Details'] = result['Analysis Details']+[str(nonvendordata)+" : These Ips are part of Vendor Ip, no need to take any action, "+str(vendordata)+" : These Ips are not part of Vendor Ip"]
                        elif len(vendordata) > 0 and len(nonvendordata) == 0 :
                            result['Analysis Details'] = result['Analysis Details']+[str(vendordata)+" : These Ips are part of Vendor Ip List, no need to take any action "]
                        elif len(vendordata) == 0 and len(nonvendordata) > 0 :
                            result['Analysis Details'] = result['Analysis Details']+[str(nonvendordata)+" : These Ips are not part of Vendor Ip List"]
                    else :
                        #result = self.dependentQueryData(timeperiod,search_array.iloc[row]['depedent_query'],host)
                        search_value = search_array.iloc[row]['dependent_query2']
                        logger.info("IPs List : {}".format(ipslistdt))
                        try :
                            search_value = str(search_value).replace("{request_host}",host)
                            search_q = str(search_value).replace("{client_ips}",ipslistdt)
                        except Exception as e:
                            logger.exception("There is some issue with splunk query formation: {} , error trace - {}".format(trendName,e))
                            continue
                        try :
                            splukResult = sq.get_result_sfcc(timeperiod,search_q.replace('\n', ''))
                        except Exception as e:
                            logger.exception("Exception occurred while connecting to splunk : %s", str(e))
                        data = []
                        knownBot = []
                        unknownBot = []
                        if not splukResult :
                            logger.info("Splunk result is empty ")
                        else :
                            for item in splukResult:
                                logger.info("INFO : {}".format(item))
                                
                                if 'INFO' in str(item) :
                                    logger.info("INFO : {}".format(item))
                                    continue
                                data.append(item)
                        for dataRest in data :
                            logger.info("dataRest['Impacted_User_agent'] : {}".format(dataRest['Impacted_User_agent']))
                            logger.info("dataRest['Client_IP'] : {}".format(dataRest['Client_IP']))
                            if 'www.google.com' in dataRest['Impacted_User_agent'] :
                                knownBot.append(dataRest['Client_IP'])
                            else :
                                unknownBot.append(dataRest['Client_IP'])
                        result['Issues Overview'] = result['Issues Overview']+["Conclusion(Optional)"]
                        if len(vendordata) > 0 and len(nonvendordata) > 0 :
                            summary_details = str(nonvendordata)+" : These Ips are part of Vendor Ip, no need to take any action, "+str(vendordata)+" : These Ips are not part of Vendor Ip , "
                            #result['Analysis Details'] = result['Analysis Details']+[str(nonvendordata)+" : These Ips are part of Vendor Ip, no need to take any action, "+str(vendordata)+" : These Ips are not part of Vendor Ip\n "]
                            if len(knownBot) > 0 and len(unknownBot) > 0 :
                                summary_details = summary_details + str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action, "+str(vendordata)+" : These Ips are unknown bot "
                                #result['Analysis Details'] = result['Analysis Details']+[str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action, "+str(vendordata)+" : These Ips are unknown bot "]
                            elif len(knownBot) > 0 and len(unknownBot) == 0 :
                                summary_details = summary_details + str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action "
                                #result['Analysis Details'] = result['Analysis Details']+[str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action "]
                            elif len(knownBot) == 0 and len(unknownBot) > 0 :
                                summary_details = summary_details + str(unknownBot)+" : These Ips are unknown bot\n"
                                #result['Analysis Details'] = result['Analysis Details']+[str(unknownBot)+" : These Ips are unknown bot\n"]
                        elif len(vendordata) > 0 and len(nonvendordata) == 0 :
                            summary_details = str(vendordata)+" : These Ips are part of Vendor Ip List, no need to take any action ,  "
                            #result['Analysis Details'] = result['Analysis Details']+[str(vendordata)+" : These Ips are part of Vendor Ip List, no need to take any action\n "]
                            if len(knownBot) > 0 and len(unknownBot) > 0 :
                                summary_details = summary_details + str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action, "+str(vendordata)+" : These Ips are unknown bot "
                                #result['Analysis Details'] = result['Analysis Details']+[str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action, "+str(vendordata)+" : These Ips are unknown bot "]
                            elif len(knownBot) > 0 and len(unknownBot) == 0 :
                                summary_details = summary_details + str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action "
                                #result['Analysis Details'] = result['Analysis Details']+[str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action "]
                            elif len(knownBot) == 0 and len(unknownBot) > 0 :
                                summary_details = summary_details + str(unknownBot)+" : These Ips are unknown bot\n"
                        elif len(vendordata) == 0 and len(nonvendordata) > 0 :
                            summary_details = str(nonvendordata)+" : These Ips are not part of Vendor Ip List , "
                            #result['Analysis Details'] = result['Analysis Details']+[str(nonvendordata)+" : These Ips are not part of Vendor Ip List\n "]
                            if len(knownBot) > 0 and len(unknownBot) > 0 :
                                summary_details = summary_details + str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action, "+str(vendordata)+" : These Ips are unknown bot "
                                #result['Analysis Details'] = result['Analysis Details']+[str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action, "+str(vendordata)+" : These Ips are unknown bot "]
                            elif len(knownBot) > 0 and len(unknownBot) == 0 :
                                summary_details = summary_details + str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action "
                                #result['Analysis Details'] = result['Analysis Details']+[str(knownBot)+" : These Ips are part of known Bot(Google), no need to take any action "]
                            elif len(knownBot) == 0 and len(unknownBot) > 0 :
                                summary_details = summary_details + str(unknownBot)+" : These Ips are unknown bot\n"
                        result['Analysis Details'] = result['Analysis Details']+[summary_details]

        logger.info("data  is: {}".format(data))
        logger.info("data  in Result dict : {}".format(result))
        newresult = services.matplotTable(result,fileName,title)
        services.uploadImagesToServiceNow(newresult,incident,sysId)
        #import pandas as pds
        #matplotlib.pyplot.switch_backend('Agg')
        #load data into a DataFrame object:
        table = pd.DataFrame(result)
        '''serviceNowNotes = {}
        serviceNowNotes['work_notes'] = table.to_json()
        json_string = json.dumps(serviceNowNotes)
        logging.info(json_string)
        sericenow.updateServiceNowData(sysId,json_string)'''
        resultStng = 'Please find the SRE Ops Bot Analysis :\n \n '
        initial =0
        for index, row in table.iterrows():
            '''if initial == 0 :
                resultStng = str(row['Issues Overview'])+"\t : "+str(row['Analysis Details'])+"\n "
            else :'''
            resultStng = resultStng + str(row['Issues Overview'])+"\t       : "+str(row['Analysis Details'])+"\n "
            #initial = initial + 1
        serviceNowNotes = {}
        serviceNowNotes['work_notes'] = resultStng
        serviceNowNotes['state'] = 'Resolved'
        json_string = json.dumps(serviceNowNotes)
        logging.info(json_string)
        sericenow.updateServiceNowData(sysId,json_string)

    '''def dependentQueryData(timeperiod, search_value,host, result) :
        
        ipslistdt = ''
        n=0
        for dataRest in data :
            if n==0 :
                ipslistdt = dataRest["Impacted_Client_IPs"]
            else :
                ipslistdt = ipslistdt+","+dataRest["Impacted_Client_IPs"]
            n=n+1
        logger.info("IPs List : {}".format(ipslistdt))
        try :
            search_value = str(search_value).replace("{request_host}",host)
            search_q = str(search_value).replace("{client_ips}",ipslistdt)
        except Exception as e:
            logger.exception("Due to some issues with query not able to get the data from splunk, error trace - {}".format(e))
        try :
            splukResult = sq.get_result_sfcc(timeperiod,search_q.replace('\n', ''))
        except Exception as e:
            logger.exception("Exception occurred while connecting to splunk : %s", str(e))
        data = []
        vendordata = []
        nonvendordata = []
        if not splukResult :
            logger.info("Splunk result is empty ")
        else :
            for item in splukResult:
                logger.info("INFO : {}".format(item))
                
                if 'INFO' in str(item) :
                    logger.info("INFO : {}".format(item))
                    continue
                data.append(item)
        for dataRest in data :
            logger.info("dataRest['vendor_traffic'] : {}".format(dataRest['vendor_traffic']))
            logger.info("dataRest['Client_IP'] : {}".format(dataRest['Client_IP']))
            if dataRest['vendor_traffic'] == "true" :
                vendordata.append(dataRest['Client_IP'])
            else :
                nonvendordata.append(dataRest['Client_IP'])
        result['Issues Overview'] = result['Issues Overview']+["Conclusion(Optional)"]
        if len(vendordata) > 0 and len(nonvendordata) > 0 :
            result['Analysis Details'] = result['Analysis Details']+[str(nonvendordata)+" : These Ips are part of Vendor Ip, no need to take any action, "+str(vendordata)+" : These Ips are not part of Vendor Ip"]
        elif len(vendordata) > 0 and len(nonvendordata) == 0 :
            result['Analysis Details'] = result['Analysis Details']+[str(vendordata)+" : These Ips are part of Vendor Ip List, no need to take any action "]
        elif len(vendordata) == 0 and len(nonvendordata) > 0 :
            result['Analysis Details'] = result['Analysis Details']+[str(nonvendordata)+" : These Ips are not part of Vendor Ip List"]
        return result'''
    # Convert string to datetime
    def parse_time(self,time_str):
        return datetime.datetime.fromisoformat(time_str)
