import xmltodict, json, html, os, hashlib, re, urllib.parse, base64

def labelToMargin(label):
	labels = {
		'Vulnerable':'10px',
		'Critical':'22px',
		'Warning':'28px',
		'Checked':'28px'
	}

	if label in labels:
		return labels[label]

def labelToColor(label):
	labels = {
		'Vulnerable':'red',
		'Critical':'black',
		'Warning':'orange',
		'Checked':'blue'
	}

	if label in labels:
		return labels[label]

def fromOSTypeToFontAwesome(ostype):
	icons = {
		'windows':'fab fa-windows',
		'solaris':'fab fa-linux',	# there isn't a better icon on fontawesome :(
		'unix':'fab fa-linux',		# same here...
		'linux':'fab fa-linux',
	}

	if ostype.lower() in icons:
		return str(icons[ostype.lower()])
	else:
		return 'fas fa-question'

def nmap_ports_stats(scanfile):
	try:
		oo = xmltodict.parse(open('/opt/xml/'+scanfile, 'r').read())
	except:
		return {'po':0,'pc':0,'pf':0}

	r = json.dumps(oo['nmaprun'], indent=4)
	o = json.loads(r)

	po,pc,pf = 0,0,0

	if 'host' not in o:
		return {'po':0,'pc':0,'pf':0}

	for ik in o['host']:
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		ss,pp,ost = {},{},{}
		lastportid = 0

		if '@addr' in i['address']:
			address = i['address']['@addr']
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					address = ai['@addr'] 

		addressmd5 = hashlib.md5(str(address).encode('utf-8')).hexdigest()

		striggered = False
		if 'ports' in i and 'port' in i['ports']:
			for pobj in i['ports']['port']:
				if type(pobj) is dict:
					p = pobj
				else:
					p = i['ports']['port']

				if lastportid == p['@portid']:
					continue
				else:
					lastportid = p['@portid']

				if 'service' in p:
					ss[p['service']['@name']] = p['service']['@name']

				pp[p['@portid']] = p['@portid']

				if p['state']['@state'] == 'closed':
					#ports['closed'] = (ports['closed'] + 1)
					pc = (pc + 1)
				elif p['state']['@state'] == 'open':
					#ports['open'] = (ports['open'] + 1)
					po = (po + 1)
				elif p['state']['@state'] == 'filtered':
					#ports['filtered'] = (ports['filtered'] + 1)
					pf = (pf + 1)

	return {'po':po,'pc':pc,'pf':pf}

def get_cve(scanmd5):
	cvehost = {}
	cvefiles = os.listdir('/opt/notes')
	for cf in cvefiles:
		m = re.match('^('+scanmd5+')_([a-z0-9]{32,32})\.cve$', cf)
		if m is not None:
			if m.group(1) not in cvehost:
				cvehost[m.group(1)] = {}

			if m.group(2) not in cvehost[m.group(1)]:
				cvehost[m.group(1)][m.group(2)] = open('/opt/notes/'+cf, 'r').read()

			#cvehost[m.group(1)][m.group(2)][m.group(3)] = open('/opt/notes/'+cf, 'r').read()

	return cvehost
