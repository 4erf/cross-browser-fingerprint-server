from flask import Flask, request,make_response, current_app
from flask_failsafe import failsafe
import flask
from flask_cors import CORS, cross_origin
import json
import hashlib
from flaskext.mysql import MySQL
import re

mysql = MySQL()
app = Flask(__name__)
app.config['MYSQL_DATABASE_USER'] = 'admin'
app.config['MYSQL_DATABASE_PASSWORD'] = '1b1d6ab9353690e49cadfb67e86a66e4e1f6e5f3ec794e29'
app.config['MYSQL_DATABASE_DB'] = 'app'
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
mysql.init_app(app)
CORS(app)

mask = []
mac_mask = []

with open("mask.txt", 'r') as f:
	mask = json.loads(f.read())
with open("mac_mask.txt", 'r') as fm:
	mac_mask = json.loads(fm.read())

def features(request, cross):
	agent = ""
	accept = ""
	encoding = ""
	language = ""
	IP = ""

	try:
		agent = request.headers.get('User-Agent')
		accept = request.headers.get('Accept')
		encoding = request.headers.get('Accept-Encoding')
		language = request.headers.get('Accept-Language')
		IP = request.remote_addr
	except:
		pass

	feature_list = [
			"IP",
			"agent",
			"accept",
			"encoding",
			"language",
			"langsDetected",
			"resolution",
			"fonts",
			"WebGL", 
			"WebGLFp",
			"WebGLVendor",
			"WebGLExtensions",
			"inc", 
			"gpu", 
			"gpuImgs", 
			"timezone",
			"timezoneOffset",	
			"plugins", 
			"cookie", 
			"localstorage",
			"adBlock",
			"cpu_cores", 
			"canvas", 
			"audio",
			"audioBrowser",
			"memory"]

	single_feature_list = [
			"agent",
			"accept",
			"encoding",
			"language",
			"resolution",
			"WebGLFp",
			"WebGLVendor",
			"WebGLExtensions",
			"plugins", 
			"canvas", 
			"audioBrowser",
			"memory",
			"timezone",
			"timezoneOffset"]
		
	cross_feature_list = [
			"fonts",
			"langsDetected",
			"audio",
			"gpuImgs",
			"cpu_cores",
			"gpu"]
	
	if not cross:
		result = request.get_json()['single']
	else:
		result = request.get_json()['cross']

	single_hash = "single"
	cross_hash = "cross"

	#with open("fonts.txt", 'a') as f:
	#f.write(result['fonts'] + '\n')

	if 'fonts' in result:
		fonts = list(result['fonts'])
		cnt = 0
		for i in range(len(mask)):
			fonts[i] = str(int(fonts[i]) & mask[i] & mac_mask[i])
			if fonts[i] == '1':
				cnt += 1

	result['agent'] = agent
	result['accept'] = accept
	result['encoding'] = encoding
	result['language'] = language
		
	print agent

	def getFeatureString(list):
		feature_str = ""
		value_str = ""
		for feature in list:
			if result[feature] is not "":
				value = result[feature]
			else:
				value = "NULL"

			feature_str += feature + ","
			#for gpu imgs
			if feature == "gpuImgs":
				value = ",".join('%s_%s' % (k,v) for k,v in value.iteritems())
			else:
				value = str(value)

			#if feature == "cpu_cores" and type(value) != 'int':
			#value = -1
			#fix the bug for N/A for cpu_cores
			if feature == 'cpu_cores':
				value = int(value)

			if feature == 'langsDetected':
				value = str("".join(value))
				value = value.replace(" u'", "")
				value = value.replace("'", "")
				value = value.replace(",", "_")
				value = value.replace("[", "")
				value = value.replace("]", "")
				value = value[1:]
				
			value_str += "'" + str(value) + "',"
			#print feature, hash_object.hexdigest()

		return [feature_str, value_str]
		
	if not cross:
		for feature in single_feature_list:
			single_hash += str(result[feature])
			hash_object = hashlib.md5(str(result[feature]))
		hash_object = hashlib.md5(single_hash)
		single_hash = hash_object.hexdigest()

		return {"single": single_hash}
	else:
		single_str_array = getFeatureString(single_feature_list)
		cross_str_array = getFeatureString(cross_feature_list)

		result['fonts'] = fonts 

		for feature in single_feature_list:
			single_hash += str(result[feature])
			hash_object = hashlib.md5(str(result[feature]))

		hash_object = hashlib.md5(single_hash)
		single_hash = hash_object.hexdigest()

		for feature in cross_feature_list:
			cross_hash += str(result[feature])
			hash_object = hashlib.md5(str(result[feature]))
		hash_object = hashlib.md5(cross_hash)
		cross_hash = hash_object.hexdigest()

		single_str_array[0] += 'browser_fingerprint'
		cross_str_array[0] += 'computer_fingerprint'
		single_str_array[1] += "'" + single_hash.replace("'", "''") + "'"
		cross_str_array[1] += "'" + cross_hash.replace("'", "''")  + "'"
		return {"single": single_hash, "cross": cross_hash, "single_str_array": single_str_array, "cross_str_array": cross_str_array}

# ROUTES
@app.route("/")
def hello():
		return "Hello World!"

@app.route("/newaccount", methods=['POST'])
def newAccount():
	result = request.get_json()
	fingerprint = features(request, True)

	db = mysql.get_db()
	cursor = db.cursor()

	sql_str = "SELECT id FROM users WHERE user = '" + result['user'] + "'"
	cursor.execute(sql_str)
	db.commit()
	for row in cursor:
		if row is not None:		
			return flask.jsonify({"result": 'userexists'})

	sql_str = "SELECT * FROM devices WHERE computer_fingerprint = '" + fingerprint['cross'] + "'"
	cursor.execute(sql_str)
	db.commit()
	for row in cursor:
		if row is not None:
			return flask.jsonify({"result": 'notunique'})
		
	sql_str = "INSERT INTO users (user) VALUES ('" + result['user'] + "');"
	cursor.execute(sql_str)
	db.commit()

	sql_str = "INSERT INTO devices (" + fingerprint["cross_str_array"][0] + ",userID) VALUES (" + fingerprint["cross_str_array"][1] + ", LAST_INSERT_ID());"
	cursor.execute(sql_str)
	db.commit()

	sql_str = "INSERT INTO browsers (" + fingerprint["single_str_array"][0] + ",deviceID) VALUES (" + fingerprint["single_str_array"][1] + ", LAST_INSERT_ID());"
	cursor.execute(sql_str)
	db.commit()
		
	cursor.close()
	return flask.jsonify({"result": 'success'})

@app.route("/login", methods=['POST'])
def login():
	result = request.get_json()
	db = mysql.get_db()
	cursor = db.cursor()

	sql_str = "SELECT id FROM users WHERE user = '" + result['user'] + "'"
	cursor.execute(sql_str)
	db.commit()
	if cursor.rowcount == 0:
		return flask.jsonify({"result": 'user dont exists'});

	if result['mode'] == 'single':
		fingerprint = features(request, False)
		sql_str = "SELECT B.browser_fingerprint FROM browsers B LEFT JOIN devices D ON B.deviceID = D.id INNER JOIN users U ON D.userID = U.id WHERE U.user = '" + result['user'] + "'"
		cursor.execute(sql_str)
		for row in cursor:
			if row is not None:
				if row[0] == fingerprint['single']:
					return flask.jsonify({"result": 'allowed'})
		return flask.jsonify({"result": 'not on account'})
	
	if result['mode'] == 'cross':
		fingerprint = features(request, True)
		sql_str = "SELECT * FROM devices WHERE computer_fingerprint = '" + fingerprint['cross'] + "'"
		cursor.execute(sql_str)
		db.commit()
		for row in cursor:
			if row is not None:
				sql_str = "INSERT INTO browsers (" + fingerprint["single_str_array"][0] + ",deviceID) VALUES (" + fingerprint["single_str_array"][1] + ",'" + str(row[0]) + "');"
				cursor.execute(sql_str)
				db.commit()
				return flask.jsonify({"result": 'browser added'})

		sql_str = "INSERT INTO devices (" + fingerprint["cross_str_array"][0] + ",userID) SELECT " + fingerprint["cross_str_array"][1] + ",id FROM users WHERE user = '" + result['user'] + "';"
		cursor.execute(sql_str)
		db.commit()
		sql_str = "INSERT INTO browsers (" + fingerprint["single_str_array"][0] + ",deviceID) VALUES (" + fingerprint["single_str_array"][1] + ", LAST_INSERT_ID());"
		cursor.execute(sql_str)
		db.commit()
		return flask.jsonify({"result": 'device added'})

	cursor.close()

@app.route("/vote", methods=['POST'])
def vote():
	result = request.get_json()
	db = mysql.get_db()
	cursor = db.cursor()
	fingerprint = features(request, False)

	sql_str = "SELECT B.browser_fingerprint FROM browsers B LEFT JOIN devices D ON B.deviceID = D.id INNER JOIN users U ON D.userID = U.id WHERE U.user = '" + result['user'] + "'"
	cursor.execute(sql_str)
	for row in cursor:
		if row is not None:
			if row[0] == fingerprint['single']:
				return flask.jsonify({"result": 'allowed'})
	return flask.jsonify({"result": 'not allowed'})

