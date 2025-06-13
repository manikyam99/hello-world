#from apscheduler.schedulers.background import BackgroundScheduler
from flask_scheduler import Scheduler

import calendar
import datetime
from flask import Flask, render_template, request
import PortalServices.services as services
from PortalServices.akamaiservice import AkamaiServices
from dateutil import parser
from logging_config import setup_logging

akamaiserv = AkamaiServices()

#app = Flask(__name__,static_folder='/Users/mani.gummalla/Desktop/Tapestry/chatbotCode/SREBot/static/')

app = Flask(__name__)

# Setup logging
setup_logging()

scheduler = Scheduler(app)

#app.config['SCHEDULER_API_INTERVAL'] = 10
@app.route("/tapestry")
def welcome_page():
    return render_template("datedisplay.html")

@app.route("/tapestry/gettime")
def getdatetime_page():
    return render_template("datedisplay.html")

@app.route("/tapestry/timedisplay")
def displayDateTime():
    region = request.args.get('region')
    regionalHost = request.args.get('host')
    hours = request.args.get('time')
    fromDate = request.args.get('fromtime')
    toDate = request.args.get('totime')
    if(len(hours) > 0):
        fromDate = ''
        toDate = ''
        epocTime = ''
    else :
        hours = ''
        epocTime = parser.parse(fromDate).timestamp()
    print("Time",epocTime)
    #print("Epoc Time : {}, Time : {}".format(calendar.timegm(datetime_object),datetime_object))
    return ("Results are {},{},{},{}, Epic Time : {}, hours : {}".format(region,regionalHost,fromDate,toDate,epocTime,hours))

@scheduler.runner(interval=600)
@app.route('/tapestry/siteoutage')
def getSiteOutageGraph():
    #data,siteOpsRes,updateRes = services.get_sitoutage_result(region,regionalHost,action,hours,epocfromTime,epoctoTime)
    services.getServiceNowIncidents()
    print('Scheduler runs in every 10 minitues')
    #return render_template("response.html")
    #return render_template("graph.html", name =data,resData=siteOpsRes,updateRes=updateRes)

@scheduler.runner(interval=86400)
@app.route('/tapestry/akamai/networkips')
def getAkamaiNetworkIps():
    akamaiserv.getAkamaiNetworkListIps()
    print('Scheduler runs in every 10 minitues')
    #return render_template("response.html")
    #return render_template("graph.html", name =data,resData=siteOpsRes,updateRes=updateRes)

#@scheduler.runner(interval=20)
def my_task():
    print('hi im running every 5 seconds')

if __name__ == "__main__":
    app.run(debug=True,use_reloader=False)
