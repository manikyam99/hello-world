import pandas as pd
import csv

class Utils():
    
    def getLabel(self, region_label):
        df_label = pd.read_csv('resources/Hostname_mapping.csv')
        df_label = df_label[(df_label['region_label']==region_label)]
        return df_label['label']
        
    def getRequestPath(self, label):
        df_path = pd.read_csv('resources/Hostname_mapping.csv')
        df_path = df_path[(df_path['Call_type']== label)]
        return df_path

    def getSplunkQuery(self, platform, trend):
        df_path = pd.read_csv('resources/query_data.csv')
        trend1 = str(trend).strip().lower()
        df_path = df_path[((df_path['platforms']== platform) & (df_path['trends']== trend1))]
        return df_path
    
    def getSplunkQueryByPlatfrom(self, platform):
        df_path = pd.read_csv('resources/query_data.csv')
        df_path = df_path[(df_path['platforms']== platform) ]
        return df_path
    
    def getServiceNowSummary(self):
        df_path = pd.read_csv('resources/servicenow_mapping.csv')
        return df_path
    
    def getSplunkQueryToCreateServiceNow(self):
        df_path = pd.read_csv('resources/createServicenowTicket.csv')
        return df_path
        
        
        
        
