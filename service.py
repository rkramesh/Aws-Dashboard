from flask import Flask, flash, abort, redirect, url_for, request, render_template, make_response, json, Response,session

#from utils import authenticate
import authenticate
import os, sys
import config
import boto.ec2.elb
import boto
import boto3
from boto.ec2 import *
app = Flask(__name__)
app.secret_key = "Hello"
@app.route("/")
@app.route("/welcome/")
##def welcome ():
##    if (len(session.keys()) > 0):
##        return redirect(url_for('index',user = session['user']))
##    else:
##        return redirect(url_for('login'))
@app.route("/home/")
def home():
    if (len(session.keys()) > 0):
        return redirect(url_for('index',user = session['user']))
    else:
        return render_template('home.html')
        
@app.route("/login/")
def login ():
    if (len(session.keys()) > 0):
        return render_template('index.html',user = session['user'])
##    return render_template('home.html')
    return redirect(url_for('home'))

@app.route("/authenticate/", methods = ['POST']) #only post requests allowed
def auth():
    if (request.form['action'] == "login"):
        out = authenticate.login(request.form['user'], request.form['password'])
        try:
            if (out[1] == 1):
                session['user'] = request.form['user']
                return redirect(url_for('index'))
        except:
##                return redirect(url_for('home'))
##                    return redirect(url_for('home', out='foo'))
                    return render_template('home.html',out='Rocky')

    elif (request.form['action'] == "register"):
        return authenticate.register(request.form['user'], request.form['password'])

@app.route("/logout/", methods = ['POST', 'GET'])
def logout():
    if (len(session.keys()) > 0):
        session.pop('user')
    return redirect(url_for('home'))

@app.route('/index')
def index():
        if (len(session.keys()) > 0):
                
                list = []
                creds = config.get_ec2_conf()
                for region in config.region_list():
                        ec2 = boto3.client('ec2', region)
                        resp = ec2.describe_availability_zones()
        #                zones=[d['ZoneName'] for d in resp['AvailabilityZones'] if d['ZoneName']]
                        zones=[d for d in resp['AvailabilityZones'] if d['ZoneName']]
                        ec2 = boto3.resource('ec2', region_name=region)
                        instances = ec2.instances.filter()
                        instances=[i.id for i in instances]
                        ebs =[ volume for instance in ec2.instances.all() for volume in instance.volumes.all()]
                        ebscount = len(ebs)
                        instance_count = len(instances)
                        
                        
                ##		instance_count = len(instances)
                ##		ebs = conn.get_all_volumes()
                ##		ebscount = len(ebs)
                        unattached_ebs = 0
                        unattached_eli = 0
                ##		event_count = 0
                ##	
                ##		for instance in instances:
                ##			events = instance.events
                ##			if events:
                ##				event_count = event_count + 1	
                        ##
                ##		for vol in ebs:
                ##			state = vol.attachment_state()
                ##			if state == None:
                ##				unattached_ebs = unattached_ebs + 1
                ##
                ##		elis = conn.get_all_addresses()
                ##		eli_count = len(elis)
                ##
                ##
                ##		for eli in elis:
                ##			instance_id = eli.instance_id
                ##			if not instance_id:
                ##				unattached_eli = unattached_eli + 1
                ##
                ##		connelb = boto.ec2.elb.connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
                ##		elb = connelb.get_all_load_balancers()
                ##		elb_count = len(elb)
                ##		list.append({ 'region' : region, 'zones': zones, 'instance_count' : instance_count, 'ebscount' : ebscount, 'unattached_ebs' : unattached_ebs, 'eli_count' : eli_count, 'unattached_eli' : unattached_eli, 'elb_count' : elb_count, 'event_count' : event_count})
                        list.append({ 'region' : region, 'zones': zones, 'instance_count' : instance_count, 'unattached_ebs' : unattached_ebs, 'unattached_eli' : unattached_eli})
                ##		
                return render_template('index.html',list=list)
        else:
                return redirect(url_for('login'))

@app.route('/ebs_volumes/<region>/')
def ebs_volumes(region=None):
	creds = config.get_ec2_conf()
	conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	ebs = conn.get_all_volumes()
	ebs_vol = []	
	for vol in ebs:
		state = vol.attachment_state()
		if state == None:
			ebs_info = { 'id' : vol.id, 'size' : vol.size, 'iops' : vol.iops, 'status' : vol.status }
			ebs_vol.append(ebs_info)
	return render_template('ebs_volume.html',ebs_vol=ebs_vol,region=region)
			
@app.route('/ebs_volumes/<region>/delete/<vol_id>')
def delete_ebs_vol(region=None,vol_id=None):
	creds = config.get_ec2_conf()	
	conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	vol_id = vol_id.encode('ascii')
	vol_ids = conn.get_all_volumes(volume_ids=vol_id)
	for vol in vol_ids:
		vol.delete()
	return redirect(url_for('ebs_volumes', region=region))
	
@app.route('/elastic_ips/<region>/')
def elastic_ips(region=None):
	creds = config.get_ec2_conf()
	conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	elis = conn.get_all_addresses()
	un_eli = []
	for eli in elis:
		instance_id = eli.instance_id
		if not instance_id:
			eli_info = { 'public_ip' : eli.public_ip, 'domain' : eli.domain}
			un_eli.append(eli_info)
	return render_template('elastic_ip.html',un_eli=un_eli,region=region)

@app.route('/elastic_ips/<region>/delete/<ip>')
def delete_elastic_ip(region=None,ip=None):
	creds = config.get_ec2_conf()
	conn = connect_to_region(region, aws_access_key_id=creds['AWS_ACCESS_KEY_ID'], aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'])
	ip = ip.encode('ascii')
	elis = conn.get_all_addresses(addresses=ip)

	for eli in elis:
		eli.release()
	return redirect(url_for('elastic_ips', region=region))
	

@app.route('/instance_events/<region>/')
def instance_events(region=None):
        Ntag=(lambda x: 'Name not Assigned' if x is None else x[0]['Value'])
        instance_event_list = []
        ec2 = boto3.resource('ec2', region_name=region)
        instances = ec2.instances.filter()
        print instances
        for i in instances:
                event_info = { 'instance_id' : i.id, 'State' : i.state['Name'], 'Region' : i.placement['AvailabilityZone'], 'Public_DNS' : i.public_ip_address, 'Private_DNS' : i.private_ip_address, 'Type': i.instance_type,'Name' : Ntag(i.tags) }
                instance_event_list.append(event_info)
        instance_list = sorted(instance_event_list, key=lambda k: k['State'])
        return render_template('instance_events.html', instance_event_list=instance_list)

@app.route('/instance_events/All/')
def instance_events_all(region=None):
        Ntag=(lambda x: 'Name not Assigned' if x is None else x[0]['Value'])
        instance_event_list_all = []
        for region in config.region_list():
                ec2 = boto3.resource('ec2', region_name=region)
                instances = ec2.instances.filter()
                for i in instances:
                        event_info_all = { 'instance_id' : i.id, 'State' : i.state['Name'], 'Region' : i.placement['AvailabilityZone'], 'Public_DNS' : i.public_ip_address, 'Private_DNS' : i.private_ip_address, 'Type': i.instance_type,'Name' : Ntag(i.tags) }
                        instance_event_list_all.append(event_info_all)
                        instance_list_all = sorted(instance_event_list_all, key=lambda k: k['State'])
#        return render_template('instance_events_all.html', instance_event_list=instance_list_all)
        return render_template('instance_events.html', instance_event_list=instance_list_all)

@app.route('/instance_events_state/<region>')
#@app.route("/instance_events_state/{{instance_event['Region']}}/{{instance_event['instance_id']}}")
def instance_events_state(region=None):
         conn = boto3.client('ec2',region_name=region.split(':')[0][:-1])
         print ("Starting Instance ({}) ".format(region.split(':')[1]))
         if region.split(':')[2]=='stopped':

                 conn.start_instances(InstanceIds=[region.split(':')[1]]) 
         else:

                 conn.stop_instances(InstanceIds=[region.split(':')[1]]) 
         return redirect(url_for('instance_events_all'))

			
if __name__ == '__main__':
	app.debug = True
	app.run(host='0.0.0.0',port=9000)
