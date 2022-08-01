$(document).ready(function() {
	// doc ready
});

var cpetot = 0;
var cpetimer;
function checkCVE() {
	if($('#cpestring').length <= 0) {
		M.toast({html: 'Please, select a scan report first'});
		return 0;
	}

	cpe = JSON.parse(atob(decodeURIComponent($('#cpestring').val())));
	csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
	console.log(cpe);

	$('#modaltitle').html('Looking for CVE and Exploits');
	$('#modalbody').html(
		'This process could take a while, please wait...'+
		'<div class="progress"><div class="indeterminate"></div></div>'
	);
	$('#modalfooter').html('');
	$('#modal1').modal('open');

	$.post('/report/api/getcve/', {
		'cpe': $('#cpestring').val(),
		'csrfmiddlewaretoken': csrftoken
	}).done(function(d) {
		console.log(d);
		$('#modalbody').html('Done. Please, reload this page by clicking on Reload button.');
		$('#modalfooter').html('<button class="btn blue" onclick="javascript:location.reload();">Reload</button>');
	});

	return 0;
	
	cpetot = Object.keys(cpe).length;
	console.log(cpetot);

	for(host in cpe) {
		for(port in cpe[host]) {
			for(cpestr in cpe[host][port]) {
				if(/^cpe:.+:.+:.+:.*$/.test(cpestr)) {
					console.log(cpestr);
					$.post('/report/api/getcve/', {
						'cpe': cpestr,
						'host':host,
						'port':port,
						'csrfmiddlewaretoken': csrftoken
					}).done(function(d) {
						console.log(d);
						for(rhost in d) {
							for(rport in d[rhost]) {
								$('#modalbody').append('<div class="small"><i>Received: '+d[rhost][rport]['id']+' host:'+rhost+' port:'+rport+'</i></div>');
							}
						}
					}).always(function() { cpetot = (cpetot - 1); });
				} else {
					cpetot = (cpetot - 1);
				}

				console.log(cpetot);
			}
		}
	}

	cpetimer = setInterval(function() {
		if(checkCPETOT()) {
			console.log('END');
			window.clearInterval(cpetimer);
			$('#modalbody').html('Done. Please, reload this page by clicking on Reload button.');
			$('#modalfooter').html('<button class="btn blue" onclick="javascript:location.reload();">Reload</button>');
		}
	}, 2000);
}

function checkCPETOT() {
	if(cpetot <= 0) {
		return true;
	} else {
		return false;
	}
}

function genPDF(md5scan) {
	if(/^[a-f0-9]{32,32}$/.test(md5scan)) {
		$.get('/report/api/pdf/').done(function(data) {
			console.log(data);
			// $('#modal1').css('background-color','#3e3e3e');
			$('#modaltitle').html('Generating PDF Report');
		
			$('#modalbody').html('Please wait a few seconds...<br>'+
			'<div class="progress"><div class="indeterminate"></div></div>'+
			'<br><br>You\'ll be redirected to the PDF Report:<br>')
			$('#modal1').modal('open');
		});

		var pdfcheck = setInterval(function() {
			$.get('/static/'+md5scan+'.pdf')
			.done(function() { $('#modalbody').append('PDF ready! Please wait...<br>'); setTimeout(function() { location.href='/static/'+md5scan+'.pdf' }, 3000); })
			.fail(function() { $('#modalbody').append('<i>PDF not ready yet...</i><br>'); });
		}, 2000);
	}
}

function removeNotes(hashstr, i) {
	$.get('/report/api/rmnotes/'+hashstr+'/').done(function(data) {
		if(data['ok'] == 'notes removed') {
			$('#noteshost'+i).remove();
		}
	});
}

function saveNotes() {
	nb64 = encodeURIComponent(btoa($('#notes').val()));
	csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
	hashstr = $('#hashstr').val();
	console.log(hashstr);
	$.post('/report/api/savenotes/', {
		'notes': nb64,
		'csrfmiddlewaretoken': csrftoken,
		'hashstr': hashstr
	 }).done(function(d) {
		console.log(d);
		if(typeof(d['ok']) !== 'undefined' && d['ok'] == 'notes saved') {
			$('#modalbody').html('<span class="green-text">Notes successfully saved!</span><br> Now this page needs a reload. Please, click on the &quot;Reload&quot; button.');
			$('#modalfooter').html('<button class="btn blue" onclick="javascript:location.reload();">Reload</button>');
		}
	});
}

function openNotes(hashstr, notesb64) {
	if(/^[a-f0-9]{32,32}$/.test(hashstr)) {
		if(notesb64 != '') {
			savednotes = atob(decodeURIComponent(notesb64));
		} else {
			savednotes = ''
		}
		// $('#modal1').css('background-color','#3e3e3e');
		$('#modaltitle').html('Save Notes');
		$('#modalbody').html(
			'In the text area below, you can insert notes that will appear on the PDF report. '+
			'All input here are <b class="blue-text">intentionally not sanitized</b>, so you can use HTML markup and JavaScript. '+
			'Please, keep in mind that <b class="orange-text">you can break the PDF View HTML</b> and, of course, this represents a stored XSS vector.<br><br>'+
			'<textarea id="notes" style="min-height:160px;border-radius:4px;border:solid #ccc 1px;padding:10px;font-family:monospace;">'+$('<span/>').text(savednotes).html()+'</textarea>'+
			'<input type="hidden" id="hashstr" value="'+hashstr+'" /><br><br>'+
			'<b>Tips:</b><br>'+
			'<code class="grey-text">&lt;b&gt;bold text&lt;/b&gt;</code> = <b>bold text</b><br>'+
			'<code class="grey-text">&lt;i&gt;italic text&lt;/i&gt;</code> = <i>italic text</i><br>'+
			'<code class="grey-text">&lt;span class="label green"&gt;A green label&lt;/span&gt;</code> = <span class="label green">A green label</span><br>'+
			'<code class="grey-text">&lt;code&gt;monospace font&lt;/code&gt;</code> = <code>monospace font</code>'
		);
		$('#modalfooter').html('<button class="modal-close waves-effect waves-green btn grey">Close</button> <button onclick="javascript:saveNotes();" class="waves-effect waves-green btn green white-text">Save</button>');
		$('#modal1').modal('open');
	}
}

function apiPortDetails(address, portid) {
	$.get('/report/api/'+address+'/'+portid+'/').done(function(data) {
		console.log(data);

		$('#modaltitle').html('Port Details: <span class="blue-text">'+$('<span/>').text(data['@protocol']).html().toUpperCase()+' / '+$('<span/>').text(data['@portid']).html()+'</span>');

		tbody = ''
		ingorescriptid = {
			'fingerprint-strings':true
		}

		console.log(typeof(data['script']));
		if(typeof(data['script']) !== 'undefined') {
			if(typeof(data['script']) === 'object' && typeof(data['script']['@id']) === 'undefined') {
				for(sid in data['script']) {
					if(typeof(ingorescriptid[data['script'][sid]['@id']]) !== 'undefined') { continue; }
					tbody += '<tr><td class="orange-text">'+$('<span/>').text(data['script'][sid]['@id']).html()+'</td><td style="font-family:monospace;font-size:12px;">'+$('<span/>').text(data['script'][sid]['@output']).html()+'</td></tr>'
				}
			} else {
				if(typeof(ingorescriptid[data['script']['@id']]) === 'undefined') {
					tbody += '<tr><td class="orange-text">'+$('<span/>').text(data['script']['@id']).html()+'</td><td style="font-family:monospace;font-size:12px;">'+$('<span/>').text(data['script']['@output']).html()+'</td></tr>'
				}
			}
		} else {
			tbody += '<tr><td><i>none</i></td><td><i>none</i></td></tr>'
		}

		// $('#modal1').css('background-color','#3e3e3e');

		$('#modalbody').html('<table class="table"><thead><th style="min-width:200px;">Script ID</th><th>Output</th></thead><tbody>'+tbody+'</tbody></table>');
		$('#modalbody').append('<br><b>Raw Output:</b><br><pre>'+$('<span/>').text(JSON.stringify(data, null, 4)).html()+'</pre>');
		$('#modal1').modal('open');
	});
}

function removeLabel(type, hashstr, i) {
	$.get('/report/api/rmlabel/'+type+'/'+hashstr+'/').done(function(data) {
		if(data['ok'] == 'label removed') {
			$('#hostlabel'+i).attr("class","")
			$('#hostlabel'+i).html("");
			$('#hostlabelbb'+i).attr("class","")
		}
	});
}

function setLabel(type, label, hashstr, i) {
	$.get('/report/api/setlabel/'+type+'/'+label+'/'+hashstr+'/').done(function(data) {
		console.log(data);
		var res = data;
		var color = 'grey'; var margin = '10px';
		if(res['ok'] == 'label set') {

			switch(res['label']) {
				case 'Vulnerable': color = 'red'; margin = '10px'; break;
				case 'Critical': color = 'black'; margin = '22px'; break;
				case 'Warning': color = 'orange'; margin = '28px'; break;
				case 'Checked': color = 'blue'; margin = '28px'; break;
			}

			// z-index:99;transform: rotate(-8deg);margin-top:-14px;margin-left:-40px;
			$('#hostlabel'+i).css("margin-left", '-40px')
			$('#hostlabel'+i).css("z-index", '99')
			$('#hostlabel'+i).css("transform", 'rotate(-8deg)')
			$('#hostlabel'+i).css("margin-top", '-14px')
			$('#hostlabel'+i).attr("class","")
			$('#hostlabel'+i).addClass('leftlabel');
			$('#hostlabel'+i).addClass(color);
			$('#hostlabel'+i).html(res['label']);

			// border-radius:0px 4px 0px 4px;z-index:98;position:absolute;width:18px;height:10px;margin-left:-48px;margin-top:-3px;
			$('#hostlabelbb'+i).css("border-radius", '0px 4px 0px 4px')
			$('#hostlabelbb'+i).css("z-index", '98')
			$('#hostlabelbb'+i).css("position", 'absolute')
			$('#hostlabelbb'+i).css("width", '18px')
			$('#hostlabelbb'+i).css("height", '10px')
			$('#hostlabelbb'+i).css("margin-left", '-54px')
			$('#hostlabelbb'+i).css("margin-top", '-3px')
			$('#hostlabelbb'+i).attr("class","")
			$('#hostlabelbb'+i).addClass(color);
		}
	});
}
