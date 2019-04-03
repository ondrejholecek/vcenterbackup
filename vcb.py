#!/usr/bin/env python2.7

###
### Utility to backup VMs from vCenter
###
### (written by Ondrej Holecek <ondrej@holecek.eu>)
###
### License: 3-clause BSD:
### Copyright (c) 2019, Ondrej Holecek
### All rights reserved.
###
### Redistribution and use in source and binary forms, with or without                  
### modification, are permitted provided that the following conditions are met:
###     * Redistributions of source code must retain the above copyright
###       notice, this list of conditions and the following disclaimer.
###     * Redistributions in binary form must reproduce the above copyright
###       notice, this list of conditions and the following disclaimer in the
###       documentation and/or other materials provided with the distribution.
###     * Neither the name of Ondrej Holecek nor the
###       names of its contributors may be used to endorse or promote products
###       derived from this software without specific prior written permission.
### 
### THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
### ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
### WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
### DISCLAIMED. IN NO EVENT SHALL Ondrej Holecek BE LIABLE FOR ANY
### DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
### (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
### LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
### ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
### (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
### SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
### 

from pyVim import connect
from pyVmomi import vim

import time
from datetime import datetime
import pytz

import re
import sys
import subprocess
import shutil
import syslog
import os
import threading
import argparse

from lxml import etree as ET



class MyError(Exception):
	def __init__(self, text, desc):
		Exception.__init__(self, text)
		self.desc = desc
	
class Terminate(Exception): pass

class vCB:
	def __init__(self, **kwargs):
		self.vcenter              = self.param_with_defaults(kwargs, 'vcenter', None, True)
		self.user                 = self.param_with_defaults(kwargs, 'user', None, True)
		self.password             = self.param_with_defaults(kwargs, 'password', None, True)
		self.to_backup            = self.param_with_defaults(kwargs, 'to_backup', None, True)

		self.stdout               = self.param_with_defaults(kwargs, 'stdout', False)
		self.inactivity_ping      = self.param_with_defaults(kwargs, 'inactivity_ping', 30)
		self.ignore_cert          = self.param_with_defaults(kwargs, 'ignore_cert', True)
		self.do_full_backups      = self.param_with_defaults(kwargs, 'do_full_backups', False)
		self.do_snapshots         = self.param_with_defaults(kwargs, 'do_snapshots', False)

		self.nfs_dir              = self.param_with_defaults(kwargs, 'nfs_dir', None, True)
		self.compressed_vm_dir    = self.param_with_defaults(kwargs, 'compressed_vm_dir', None, True)
		self.compress_command     = self.param_with_defaults(kwargs, 'compress_command', None, True)
		self.backup_folder        = self.param_with_defaults(kwargs, 'backup_folder', None, True)
		self.backup_datastore     = self.param_with_defaults(kwargs, 'backup_datastore', None, True)

		#
		self.si = None
		self.thr_ping = None

		if self.ignore_cert:
			import requests
			from requests.packages.urllib3.exceptions import InsecureRequestWarning
			requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
			import ssl
			ssl._create_default_https_context = ssl._create_unverified_context
			context = ssl.create_default_context()
			context.check_hostname = False
			context.verify_mode = ssl.CERT_NONE

	def destroy(self):
		self.stop_ping()

	def param_with_defaults(self, kwargs, name, default, raise_error=False):
		if name in kwargs: return kwargs[name]
		elif raise_error: 
			raise MyError("Cannot find parameter value", "Parameter \"%s\" is missing" % (name,))
		else:
			return default

	def construct_command(self, cmd, variables):
		r = re.compile('^(.*?)\${(.*?)}(.*)$')
		while True:
			g = r.search(cmd)
			if g == None: break

			try:
				cmd = g.group(1) + variables[g.group(2)] + g.group(3)
			except IndexError:
				cmd = g.group(1) + g.group(3)
				
		return cmd
	
	#
	# Thread to keep the connection alive
	#
	def start_ping(self):
		if self.inactivity_ping == 0:
			self.log("vCenter session keepalive is disabled")
			return

		self.log("Starting vCenter session keepalive")
		self.thr_ping = threading.Thread(target=self.keep_active_thread)
		self.thr_ping_running = True
		self.thr_ping.start()
	
	def stop_ping(self):
		if self.thr_ping == None: return
		self.log("Stopping vCenter session keepalive")
		self.thr_ping_running = False
		self.thr_ping.join()

	def keep_active_thread(self):
		while self.thr_ping_running:
			current_session = self.si.content.sessionManager.currentSession
			inactive = (pytz.UTC.localize(datetime.utcnow())-(current_session.lastActiveTime)).total_seconds()
			if inactive > self.inactivity_ping:
				self.log("Session inactive for %i seconds, pinging" % (int(round(inactive)),))
				self.si.content.sessionManager.SessionIsActive(current_session.key, self.user)
				continue

			time.sleep(1)

	#
	# vCenter connection
	#
	def is_logged_in(self):
		if self.si == None: return False

		current_session = self.si.content.sessionManager.currentSession
		if current_session == None: return False

		sessionid = current_session.key
		if sessionid == None: return False
		
		return self.si.content.sessionManager.SessionIsActive(sessionid, self.user)

	def connect(self):
		self.log("Logging in to vCenter server at \"%s\" as user \"%s\"" % (self.vcenter, self.user,))
		try:
			self.si = connect.SmartConnect(host=self.vcenter, user=self.user, pwd=self.password)
		except vim.fault.InvalidLogin:
			self.log("Invalid user name or password when logging in to \"%s\" as \"%s\"" % (self.vcenter, self.user,), syslog.LOG_ERR)
			raise Terminate()

		if self.backup_folder != None and self.backup_datastore != None:
			self.log("Looking for the backup folder")
			self.obj_backup_folder = self.get_folder(self.backup_folder)
			if self.obj_backup_folder == None:
				self.log("Warning: Backup folder was not found, machines will not be cloned", syslog.LOG_ERR)
		
			self.log("Looking for the backup datastore")
			self.obj_backup_datastore = self.get_datastore(self.backup_datastore)
			if self.obj_backup_datastore == None:
				self.log("Warning: Backup datastore was not found, machines will not be cloned", syslog.LOG_ERR)

		else:
			self.obj_backup_folder = None
			self.obj_backup_datastore = None

		self.start_ping()

	#
	# vSphere functions
	#
	def get_all(self, vimtype):
		obj = {}
		content = self.si.RetrieveContent()
		container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
		for managed_object_ref in container.view:
			obj.update({managed_object_ref: managed_object_ref.name})
		return obj

	def get_all_hosts(self):
		hosts = {}
		for host in self.get_all([vim.HostSystem]):
			hosts[str(host)] = host.summary.config.name
		return hosts

	def get_vms_on_host(self, hostname):
		our_host = None
		for host in vcb.get_all([vim.HostSystem]):
			if host.summary.config.name == hostname:
				our_host = host
		if our_host == None: return []

		vms = []
		for vm in vcb.get_all([vim.VirtualMachine]):
			if str(vm.runtime.host) != str(our_host): continue
			vms.append(vm)
		return vms

	def handle_task(self, task):
		while True:
			if task.info.state == 'success':
				break
			elif task.info.state == 'error':
				break
			else:
				time.sleep(1)
			
		if task.info.state == 'error':
			raise MyError("Task ended up with an error", task.info.error.msg,)

		return task.info.result
	
	def get_all_snapshots(self, vm, roots=None):
		if roots == None: roots = vm.snapshot.rootSnapshotList
		if roots == None: return []

		ss = []
		for root in roots:
			ss.append({
				'obj'     : root,
				'name'    : root.name, 
				'created' : root.createTime,
			})

			ss += self.get_all_snapshots(vm, root.childSnapshotList)

		return ss
	
	def get_folder(self, name):
		for f in self.get_all([vim.Folder]):
			if f.name == name: return f
		return None

	def get_datastore(self, name):
		for f in self.get_all([vim.Datastore]):
			if f.name == name: return f
		return None

	def get_directory(self, vm):
		dspath = vm.config.files.vmPathName
		
		g = re.search('^\[(.*?)\]\s+(.*)/(.*\.vmx)$', dspath)
		if g == None: raise MyError("Unable to parse VM filesystem", "VMX path \"%s\" is unparsable" % (dspath,))
		return (g.group(1), g.group(2), g.group(3))

	def create_current_snapshot(self, vm, snapname):
		name = vm.config.name

		self.log("%s: Creating snapshot \"%s\"" % (name, snapname,))
		task = vm.CreateSnapshot_Task(snapname, "Automatic snapshot from Backup system", memory=False, quiesce=True)
		return self.handle_task(task)

	def delete_old_snapshots(self, vm, max_age, ignore=[]):
		name = vm.config.name
		now = pytz.UTC.localize(datetime.utcnow())

		stats = {
			'removed' : 0,
			'errors'  : 0,
			'ignored' : 0,
		}

		for snap in self.get_all_snapshots(vm):
			# never delete the latest snapshot regardless on time it was take
			if str(snap['obj'].snapshot) in ignore: continue

			# don't delete snapshot not created by backup
			if not snap['name'].startswith("backup_"):
				self.log("%s: Ignoring snapshot \"%s\"" % (name, snap['name'],))
				stats['ignored'] += 1
				continue

			#
			if (now-snap['created']).total_seconds() > max_age:
				self.log("%s: Deleting old snapshot \"%s\"" % (name, snap['name'],))
				task = snap['obj'].snapshot.RemoveSnapshot_Task(removeChildren = False)
				try:
					result = self.handle_task(task)
				except MyError, e:
					self.log("%s: Cannot remove snapshot \"%s\": \"%s\"" % (name, snap['name'], e.desc,), syslog.LOG_ERR)
					stats['errors'] += 1
				else:
					self.log("%s: Snapshot \"%s\" removed" % (name, snap['name'],))
					stats['removed'] += 1

		return stats
	
	def get_disks_info(self, vm):
		units = {}
		for hw in vm.config.hardware.device:
			if type(hw) != vim.vm.device.VirtualDisk: continue
			units[hw.unitNumber] = hw
		return units

	def clone_vm(self, vm, newname, snapshot, replace):
		# If some disk positions are to be replace with new file
		# do not copy the disk, just link it
		disks = self.get_disks_info(vm)
		disks_spec = []
		for i in sorted(disks.keys()):
			if i in replace:
				disks_spec.append(vim.VirtualMachineRelocateSpecDiskLocator(
					diskId = disks[i].key,
					datastore = self.obj_backup_datastore,
					diskMoveType = 'createNewChildDiskBacking',
				))
			else:
				disks_spec.append(vim.VirtualMachineRelocateSpecDiskLocator(
					diskId = disks[i].key,
					datastore = self.obj_backup_datastore,
					diskMoveType = 'moveAllDiskBackingsAndConsolidate',
				))

		# Clone it
		name = vm.config.name
		self.log("%s: Cloning to backup datastore as \"%s\"" % (name, newname,))
		task = vm.CloneVM_Task(name=newname, folder=self.obj_backup_folder, spec=vim.VirtualMachineCloneSpec(
			location=vim.VirtualMachineRelocateSpec(
				datastore = self.obj_backup_datastore,
				disk = disks_spec,
			),
			powerOn=False,
			snapshot=snapshot,
		))
		newvm = self.handle_task(task)

		# Remove the disks in the new vm
		(vm_ds, vm_dir, tmp2) = self.get_directory(newvm)
		disks = self.get_disks_info(vm)
		change_spec_1 = []
		change_spec_2 = []
		for i in sorted(disks.keys()):
			if i not in replace: continue

			change_spec_1.append(vim.VirtualDeviceConfigSpec(
				device = vim.vm.device.VirtualDisk(
					key = disks[i].key,
				),
				fileOperation = "destroy",
				operation = "remove",
			))

			change_spec_2.append(vim.VirtualDeviceConfigSpec(
				device = vim.vm.device.VirtualDisk(
					key = disks[i].key,
					backing = vim.VirtualDiskFlatVer2BackingInfo(
						fileName = "[%s] %s/empty-%i.vmdk" % (vm_ds, vm_dir, int(time.time()),),
						datastore = self.obj_backup_datastore,
						diskMode = 'persistent',
						thinProvisioned = True,
					),
					controllerKey = disks[i].controllerKey,
					unitNumber = disks[i].unitNumber,
					capacityInKB = disks[i].capacityInKB,
				),
				fileOperation = "create",
				operation = "add",
			))


		# This must be split into two steps otherwise strange error is thrown
		if len(change_spec_1) > 0:
			self.log("%s: Removing some disks from the cloned VM" % (name,))
			task = newvm.ReconfigVM_Task(spec=vim.VirtualMachineConfigSpec(deviceChange = change_spec_1))
			self.handle_task(task)

		if len(change_spec_2) > 0:
			self.log("%s: Creating some empty disks from the cloned VM" % (name,))
			task = newvm.ReconfigVM_Task(spec=vim.VirtualMachineConfigSpec(deviceChange = change_spec_2))
			self.handle_task(task)

		# Return new vm
		return newvm


	def unregister_vm(self, vm, origname):
		newname = vm.config.name
		self.log("%s: Unregistering new VM \"%s\" from vCenter" % (origname, newname,))
		vm.UnregisterVM()

	#
	# Other
	#
	def log(self, msg, prio=syslog.LOG_INFO):
		syslog.syslog(prio, msg)
		if self.stdout: print datetime.now(), msg
		elif (prio <= syslog.LOG_ERR): print >>sys.stderr, datetime.now(), msg 

	def get_all_vms_to_backup(self):
		vms = []

		self.log("Loading information about VMs")
		hosts = self.get_all_hosts()
		for vm in self.get_all([vim.VirtualMachine]):
			if vm.config == None:
				self.log("Unable to get configuration parameters for VM \"%s\", skipping" % (str(vm),), syslog.LOG_WARNING)
				continue

			vmname = vm.config.name
			try:
				hostname = hosts[str(vm.runtime.host)]
			except KeyError:
				hostname = vm.runtime.host.summary.config.name
				hosts[str(vm.runtime.host)] = hostname

			vms.append({
				'vm' : {
					'name'  : vmname,
					'obj'   : vm,
				},
				'host' : {
					'name'  : hostname,
					'obj'   : vm.runtime.host,
				},
				'restrictions': {
					'only_running'  : False,
					'has_datastore' : False,
					'full_backup'   : False,
					'replace_disks' : [],
				},
			})

		self.log("Found %i VMs in total" % (len(vms),))

		# Find the hosts that are connected to our backup datastore
		datastore_hosts = []
		for dh in self.obj_backup_datastore.host:
			try:
				datastore_hosts.append(hosts[str(dh)])
			except KeyError:
				hostname = dh.key.summary.config.name
				datastore_hosts.append(hostname)
				hosts[str(dh)] = hostname

		# Copy only those matching the filters
		vms_to_backup = []
		for vm in vms:
			for tb in self.to_backup:
				matching = False

				if tb['type'] == 'vm' and 'name' in tb and tb['name'] == vm['vm']['name']: matching = True
				if tb['type'] == 'vm' and 'regex' in tb and re.search(tb['regex'], vm['vm']['name']) != None: matching = True
				if tb['type'] == 'host' and 'name' in tb and tb['name'] == vm['host']['name']: matching = True
				if tb['type'] == 'host' and 'regex' in tb and re.search(tb['regex'], vm['host']['name']) != None: matching = True

				if not matching: continue

				if 'only_running' in tb and tb['only_running'] == True:
					vm['restrictions']['only_running'] = True
				else:
					vm['restrictions']['only_running'] = False

				if 'full_backup' in tb and tb['full_backup'] == True:
					vm['restrictions']['full_backup'] = True
				else:
					vm['restrictions']['full_backup'] = False

				if 'replace_disks' in tb:
					vm['restrictions']['replace_disks'] = tb['replace_disks']
				else:
					vm['restrictions']['replace_disks'] = []

				if 'delete_old_snapshots' in tb:
					vm['restrictions']['delete_old_snapshots'] = tb['delete_old_snapshots']
				else:
					vm['restrictions']['delete_old_snapshots'] = None

				if vm['host']['name'] in datastore_hosts:
					vm['restrictions']['has_datastore'] = True
				else:
					vm['restrictions']['has_datastore'] = False

				vms_to_backup.append(vm)
				break

		self.log("Selected %i VMs to backup" % (len(vms_to_backup),))
		return vms_to_backup

	def do_backup(self):
		vms = self.get_all_vms_to_backup()
		for vminfo in vms:
			name = vminfo['vm']['name']
			vm   = vminfo['vm']['obj']
			self.log("Found VM \"%s\"" % (name,))
	
			# Ignore VMs that look like from previous backup
			if re.search('_\d\d\d\d-\d\d-\d\d_\d\d:\d\d:\d\d$', name):
				self.log("%s: VM looks like it is from previous backup attempt, ignoring" % (name,))
				continue

			# Accept only VMs that are running
			if vminfo['restrictions']['only_running'] and vm.runtime.powerState != 'poweredOn':
				self.log("%s: VM is not running, ignoring" % (name,))
				continue

			#
			datename = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
	
			#
			if self.do_snapshots:
				# Create current snapshot
				snapname = datename + datetime.now().strftime("_%Y-%m-%d_%H:%M:%S")
				try:
					result = self.create_current_snapshot(vm, snapname)
				except MyError, e:
					self.log("%s: Cannot create snapshot: \"%s\"" % (name, e.desc,), syslog.LOG_ERR)
					continue
				else:
					self.log("%s: Snapshot created" % (name,))
					latest_snapshot = result
	
				# Remove too old snapshots
				if vminfo['restrictions']['delete_old_snapshots'] != None:
					stats = self.delete_old_snapshots(vm, vminfo['restrictions']['delete_old_snapshots'], [str(latest_snapshot)])
					if stats['errors'] > 0:
						self.log("%s: There were errors when removing snapshots, but continuing anyway" % (name,), syslog.LOG_WARNING)
				else:
					self.log("%s: Removing old snapshots is disabled" % (name,))

			else:
				self.log("%s: Snapshots are disabled by command line parameter" % (name,))
				latest_snapshot = None
	
			if self.do_full_backups:
				# Some VMs do not have full backup enabled
				if vminfo['restrictions']['full_backup'] == False:
					self.log("%s: Full backup is disabled for this VM" % (name,))
					continue
	
				# We cannot continue if we haven't found some objects or if the ESXi host does not have the datastore connected
				if self.obj_backup_folder == None or self.obj_backup_datastore == None: 
					self.log("%s: No backup folder or datastore found, not backing up the VM" % (name,), syslog.LOG_WARNING)
					continue
	
				if vminfo['restrictions']['has_datastore'] == False:
					self.log("%s: Cannot do full VM backup because the backup datastore is not connected to this ESXi host" % (name,), syslog.LOG_WARNING)
					continue
		
				# Clone VM from the latest snapshot
				try:
					newname = "%s_%s" % (name, datename,)
					result = self.clone_vm(vm, newname, latest_snapshot, vminfo['restrictions']['replace_disks'])
				except MyError, e:
					self.log("%s: Cannot clone to \"%s\": \"%s\"" % (name, newname, e.desc,), syslog.LOG_ERR)
					continue
				else:
					newvm = result
					self.log("%s: Machine cloned to \"%s\"" % (name, newvm.config.name,))
	
				# Get directory to backup
				try:
					(tmp1, directory, tmp2) = self.get_directory(newvm)
				except MyError, e:
					self.log("%s: Cannot extract the directory: %s" % (name, e.desc,), syslog.LOG_ERR)
					continue
		
				# Remove from vCenter
				self.unregister_vm(newvm, name)
		
				# Compress local files
				cmd = self.construct_command(self.compress_command, {
					'nfs'    : self.nfs_dir,
					'vm'     : directory,
					'backup' : self.compressed_vm_dir,
				})
				self.log("%s: Compressing the VM data using command: %s" % (name, cmd,))
				try:
					subprocess.check_output(cmd, shell=True)
				except subprocess.CalledProcessError, e:
					self.log("%s: Cannot compress the VM data: %s" % (name, e.output,), syslog.LOG_ERR)
					continue
		
				# Delete the original directory
				self.log("%s: Deleting the cloned directory \"%s/%s\"" % (name, self.nfs_dir, directory,))
				shutil.rmtree("%s/%s" % (self.nfs_dir, directory,), ignore_errors=True, onerror=None)

			else:
				self.log("%s: Full backups are disabled by command line parameter" % (name,))

def make_bool(s):
	if s == None: return False
	if s.strip().lower() == 'true': return True
	if s.strip().lower() == 'yes': return True
	if s.strip() == '1': return True
	return False

def make_seconds(s):
	r = re.compile('^(\d+)([smhd]?)$')
	g = r.search(s.lower())
	if g == None: return None

	if g.group(2) in ('s',''): return int(g.group(1))
	if g.group(2) == 'm': return int(g.group(1))*60
	if g.group(2) == 'h': return int(g.group(1))*60*60
	if g.group(2) == 'd': return int(g.group(1))*60*60*24

if __name__ == '__main__':
	
	parser = argparse.ArgumentParser(description='VMware vCenter VMs backup tool.')
	parser.add_argument('--config', default="/etc/vcb.xml", help='Path to the config file, default /etc/vcb.xml')
	parser.add_argument('--keepalive', default=60, type=int, help='After # seconds of inactivity send simple request to vCenter to keep the session alive; 0 to disable')
	parser.add_argument('--stdout', action='store_true', default=False, help='Enable log writing also to stdout')
	parser.add_argument('--do-snapshots', action='store_true', default=False, help='Enable taking snapshots')
	parser.add_argument('--do-full-backups', action='store_true', default=False, help='Enable taking full backups')
	args = parser.parse_args()

	tree = ET.parse(args.config)
	root = tree.getroot()

	# Validate the config file
	# with that we do not have to deal with a lot of XML errors
	xsd = os.path.abspath(__file__).rsplit('/', 1)[0] + "/vcb.xsd"
	schema = ET.XMLSchema(ET.parse(xsd))
	try: schema.assertValid(tree)
	except ET.DocumentInvalid, di:
		print >>sys.stderr, "Config file \"%s\" does not validate to \"%s\" definition file.\nErrors follow:" % (args.config, xsd,)
		print >>sys.stderr, str(di)
		sys.exit(1)
	
	# Prepare backup definition
	to_backup = []
	backup = tree.find('./backup')
	for el in backup:
		if el.tag not in ('vm', 'host'): 
			continue

		tmp = {
			'type': el.tag,
		}

		# default from <backup> attribute
		if 'only_running' in el.attrib: tmp['only_running'] = make_bool(el.attrib['only_running'])
		elif 'only_running' in backup.attrib: tmp['only_running'] = make_bool(backup.attrib['only_running'])
		else: tmp['only_running'] = False

		if 'full_backup' in el.attrib: tmp['full_backup'] = make_bool(el.attrib['full_backup'])
		elif 'full_backup' in backup.attrib: tmp['full_backup'] = make_bool(backup.attrib['full_backup'])
		else: tmp['full_backup'] = True

		if 'delete_old_snapshots' in el.attrib: tmp['delete_old_snapshots'] = make_seconds(el.attrib['delete_old_snapshots'])
		elif 'delete_old_snapshots' in backup.attrib: tmp['delete_old_snapshots'] = make_seconds(backup.attrib['delete_old_snapshots'])
		else: tmp['delete_old_snapshots'] = None

		# not overridable
		if 'type' in el.attrib and el.attrib['type'] == 'regex': tmp['regex'] = el.text
		else: tmp['name'] = el.text

		tmp['replace_disks'] = []
		if 'replace_disks' in el.attrib:
			for position in el.attrib['replace_disks'].split(','):
				try: tmp['replace_disks'].append(int(position.strip()))
				except: pass

		to_backup.append(tmp)

	#
	vcb = vCB(
		vcenter           = tree.findtext('./vcenter/host'),
		user              = tree.findtext('./vcenter/user'),
		password          = tree.findtext('./vcenter/password'),
		ignore_cert       = make_bool(tree.findtext('./vcenter/ignore_certificate')),
		stdout            = args.stdout,
		inactivity_ping   = args.keepalive,

		do_snapshots      = args.do_snapshots,
		do_full_backups   = args.do_full_backups,

		to_backup         = to_backup,

		nfs_dir           = tree.findtext('./local/nfs_directory'),
		compressed_vm_dir = tree.findtext('./local/compressed_vm_directory'),
		compress_command  = tree.findtext('./local/compress_command'),
		backup_folder     = tree.findtext('./vcenter/backup_folder'),
		backup_datastore  = tree.findtext('./vcenter/backup_datastore'),
	)

	try:
		vcb.connect()
		vcb.do_backup()
	except KeyboardInterrupt:
		vcb.log("Interrupted from keyboard")
		pass
	except Terminate:
		pass
	finally:
		vcb.destroy()
