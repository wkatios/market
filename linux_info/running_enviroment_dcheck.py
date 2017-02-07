#coding=utf-8
#!/usr/bin/env python
##################################################
##Running Enviroment Test Script
##Run it as root or sudo
##HuiLi 2014-10-22
##Katios modified 2016-11-22
##################################################
import os
import sys
#import subprocess
import re
import json

class Enviroment(object):
    
    def __init__ (self):
        if os.getuid() != 0:
            wrong_user = 'Please run this script as root, thanks !'
            self.color(wrong_user, 0)
            sys.exit(1)
        else:
            right_user = '############################## \
            Now, iProbe running enviroment testing start \
            ##############################'
            self.color(right_user, 2)

    def color(self, string, flag):                                  #设置颜色
        if flag == 0:
            print '\033[1;31;40mWARNING!!!!',string,'\033[0m'       #红色
        elif flag == 1:
            print '\033[1;32;40mCheers!!!',string,'\033[0m'         #绿色
        elif flag == 2:
            print '\033[1;34;40m',string,'\033[0m'                  #蓝色
        else:
            print 'Wrong script !'

    def os(self):
        arch_pattern = '^Architecture:\s+(\w.*)'
        ht_pattern = 'Thread\(s\)\s+per\s+core:\s+(\d+)'
        os_pattern = (arch_pattern, ht_pattern)
#        os_fd = subprocess.Popen('lscpu', stdout = subprocess.PIPE).stdout
        os_fd = os.popen('lscpu')
        for eachLine in os_fd.readlines():
            for eachPattern in os_pattern:                          #检查系统位数
                match = re.match(eachPattern, eachLine)
                if match is not None:
                    if eachPattern == arch_pattern:
                        arch = match.group(1)
                        if arch == 'x86_64':
                            self.color('Linux OS: 64bit', 1)
                        else:
                            self.color('Linux OS: 32bit', 2)
                    elif eachPattern == ht_pattern:                 #检查超线程是否关闭
                        ht = int(match.group(1))
                        if ht != 1:
                            self.color('Hyper-Threading: HT not disabled, Please check it', 0)
                        elif ht == 1:
                            self.color('Hyper-Threading: HT already disabled', 1)
                        else:
                            self.color('Hyper-Threading: lscpu error, Please check it', 0)
                    else:
                        self.color('lscpu pattern match error', 0)
        os_fd.close()

    def memory(self):
        mem = '^Mem:\s+(\d+)?.*'
        swap = '^Swap:\s+(\d+)?.*'
        mem_pattern = (mem, swap)
        mem_fd = os.popen('free')
        for eachMem in mem_fd.readlines():
            for eachPattern in mem_pattern:
                info = re.match(eachPattern, eachMem)
                if info is not None:    
                    if eachPattern == mem:                             # 检查物理内存内存是否充足
                        mems = int(info.group(1)) / (1024 * 1024)
                        if mems > 10:
                            self.color('Memory Total: %sG' %mems, 1)
                        else:
                            self.color('Memory Total: only %sG' %mems, 0)
                    elif eachPattern == swap:                           #检查虚拟内存是否充足
                        swaps = int(info.group(1)) / (1024 * 1024)
                        if swaps > 10:
                            self.color('Swap Total: %sG' %swaps, 1)
                        else:
                            self.color('Swap Total: only %sG' %swaps, 0)
                    else:
                        self.color('Memory pattern match wrong')
        mem_fd.close()
                                            

    def numa(self):
        core = '^CPU\(s\):\s+(\d+)'
        cpu = '^NUMA\s+node\(s\):\s+(\d+)'
        numa = '^NUMA\s+node(\d+)\s+CPU\(s\):\s+(\d.*)'
        numa_pattern = (core, cpu, numa)
#        numas = {}
        numa_fd = os.popen('lscpu')
        for eachNuma in numa_fd.readlines():
            for eachPattern in numa_pattern:
                info = re.match(eachPattern, eachNuma)
                if info is not None:
                    if eachPattern == core:
                        cores = info.group(1)
                        self.color('Cores Total: %s' %cores, 1)
                    elif eachPattern == cpu:
                        cpus = info.group(1)
                        self.color('Cpus Total: %s' %cpus, 1)
                    elif eachPattern == numa:
                        numa_id = info.group(1)
                        numas = info.group(2)
                        self.color('Numa Cpu%s: %s' %(numa_id, numas), 1)
                    else:
                        self.color('Wrong pattern match about function numa', 0)
        numa_fd.close()
                        
    def core(self):
        cfg_file = '/usr/local/etc/pprobe.cfg'
        dfa_core = []
        nfcapd_core = []

        if (os.path.isfile(cfg_file)):
           core_fd = open(cfg_file, 'r')
           cfg = json.load(core_fd)
           core_fd.close()
#           nic_fd = subprocess.Popen('ifconfig', stdout = subprocess.PIPE).stdout
           nic_fd = os.popen('ifconfig')
           for ic in nic_fd.readlines():
               for nic in cfg['interfaces']:
                   if nic in ic:
                       node = os.popen('cat /sys/class/net/%s/device/numa_node' %nic).read()
                       node = node.strip()
                       self.color('Connection: nic %s connected with cpu %s' %(nic, node), 1)
                       self.color('Dfa_tcp Nic: Data nic interface %s' %nic, 1)
        #               print nic
                       self.mtu(nic)
                       self.flow(nic)
                       kernel = os.popen('uname -r').read().strip()
                       kernel_path = '/lib/modules/' + kernel + '/kernel/drivers/net/'
                       if re.search('xge', nic):
                           version = '10G'
                       elif re.search('igb', nic):
                           version = '1G'
                       else:
                           version = '100M'
           self.color('iProbe Version: %s' %version, 1)
           if version == '10G':
               affinity_py = kernel_path + 'ps_ixgbe/affinity.py'
               ps_ixgbe = kernel_path + 'ps_ixgbe/ps_ixgbe.ko'
               install_py = kernel_path + 'ps_ixgbe/install.py'
               for xge in (affinity_py, ps_ixgbe, install_py):
                   self.exist(xge)
           elif version == '1G':
              affinity_py = kernel_path + 'ps_igb/affinity.py'
              ps_igb = kernel_path + 'ps_igb/ps_igb.ko'
              set_affinity = kernel_path + 'ps_igb/set_affinity.sh'
              load_driver = '/usr/local/bin/load_driver.py'
              for igb in (affinity_py, ps_igb, set_affinity, load_driver):
                  self.exist(igb)
           else:
              pass

           nic_fd.close()
           i = 0
           for p in ('ap', 'hp', 'op', 'tcp'):
               dfa_core.append(cfg['cpu'][p + '_core_id'])
               self.color('Dfa_tcp %s core id: %s' %(p, dfa_core[i]), 1)
               i += 1
           j = 0
           for np in ('ip', 'ap', 'op'):
               nfcapd_core.append(cfg['cpu']['nfcapd_' + np + '_core_id'])
               self.color('Nfcapd %s core id: %s' %(np, nfcapd_core[j]), 1)
               j += 1
           python_fd = os.popen('pgrep nfcapd')
           k = 0
           for eachPython in python_fd.readlines():
               py_pid = os.popen('ps -eo pid,psr | grep %s' %eachPython).read().strip()
               if k == 0:
                   self.color('Mainid and core id: ' + py_pid, 1)
                   k += 1
               else:
                   self.color('Python and core id: ' + py_pid, 1)


    def mtu(self, nic):
        rec = '(generic-receive-offload):\s+(\w+)'
        tcp = '(tcp-segmentation-offload):\s+(\w+)'
        udp = '(udp-fragmentation-offload):\s+(\w+)'
        seg = '(generic-segmentation-offload):\s+(\w+)'
        lar = '(large-receive-offload):\s+(\w+)'
        pkt = (rec, tcp, udp, seg, lar)
        
#        mtu_fd = subprocess.Popen('ethtool -k ' + nic, stdout = subprocess.PIPE).stdout
        mtu_fd = os.popen('ethtool -k ' + nic)
        for eachLine in mtu_fd.readlines():
            for eachPattern in pkt:
                info = re.match(eachPattern, eachLine)
                if info is not None:
                    name = info.group(1)
                    switch = info.group(2)
                    if switch == 'off':
                        self.color('Capture Pkts %s:  %s switch is off' %(nic, name), 1)
                    else:
                        self.color('Capture Pkts %s:  %s switch is on, Please check it' %(nic, name), 0)
        mtu_fd.close()

    def flow(self, nic):
        au = '(Autonegotiate):\s+(\w+)'
        rx = '(RX):\s+(\w+)'
        tx = '(TX):\s+(\w+)'
        pattern = (au, rx, tx)
        flow_fd = os.popen('ethtool -a ' + nic)
        for eachLine in flow_fd.readlines():
            for eachPattern in pattern:
                info = re.match(eachPattern, eachLine)
                if info is not None:
                    name = info.group(1)
                    switch = info.group(2)
                    if switch == 'off':
                        self.color('Flow Control %s:  %s switch is off' %(nic, name), 1)
                    else:
                        self.color('Flow Control %s:  %s switch is on, Please check it' %(nic, name), 0)
        flow_fd.close()

    def exist(self, f):                                                 #判断文件是否存在
        if (os.path.isfile(f)):
            self.color('File: %s is ready' %f, 1)
        else:
            self.color('File: %s not found, please check it' %f, 0)

    def direxist(self, p):                                              #判断目录是否存在
        if (os.path.isdir(p)):
            self.color('Dir: %s is ready' %p, 1)
        else:
            self.color('Dir: %s not found, please check it' %p, 0)

    def probe(self):                                                    #检查文件或者目录是否存在
        bin_dir = '/usr/local/bin/'
        etc_dir = '/usr/local/etc/'
        lnmp_dir = '/usr/local/'
        dfa_tcp = bin_dir + 'dfa_tcp'
        pprobe_cfg = etc_dir + 'pprobe.cfg'
        lnmp_php = lnmp_dir + 'php'
        lnmp_nginx = lnmp_dir + 'nginx'
        lnmp_zend = lnmp_dir + 'zend'
        lnmp_bin = lnmp_dir + 'lnmp'
        nfcapd_py = bin_dir + 'nfcapd.py'
        nfsen = bin_dir + 'nfsen'
        nfsend = bin_dir + 'nfsend'
        pysocket = bin_dir + 'pysocket.py'
        nfsen_conf = etc_dir + 'nfsen.conf'
        nfsen_ini = etc_dir + 'nfsen.ini'
        data_file = '/home/juyun/datafile'
        iProbe_file = (dfa_tcp, pprobe_cfg, \
        nfcapd_py, nfsen_ini, pysocket)
        iProbe_dir = (lnmp_php, lnmp_nginx, lnmp_bin, data_file)
        for f in iProbe_file:
            self.exist(f)
        for p in iProbe_dir:
            self.direxist(p)

    def port_check(self,port):                             #检查端口在防火墙是否开放
        flag = 0
        patt = '^-A.*\s+%s\s+.*ACCEPT'%port
        iptables_fd = open('/etc/sysconfig/iptables', 'r')
        for eachWall in iptables_fd.readlines():
            if re.match(patt,eachWall) is not None:
                #self.color('Iptables: %s port is open'%port, 1)
                flag += 1
        if flag == 0:
            self.color('Iptables: %s port is not open, please check it'%port, 0)
        elif flag == 1:
            self.color('Iptables: %s port is open'%port, 1)
        else:
            self.color('Iptables: %s port is open, but there are %s same rules'%(port,flag),0)
        iptables_fd.close()

    def iptables(self):                                      #检查80 ，27017端口是否开放
        for port_num in ['80', '27017']:    
            self.port_check(port_num)
        #self.port_check('27017')

    def server_restart(self):                                 #设置开机绑定驱动
        info = os.popen('cat /etc/rc.local')
        patt1 = '^#.*'
        patt2 = '^\n'
        self.color('/etc/rc.local config, please check it:', 0)
        for line in info.readlines():
            if (re.search(patt1,line) is None) and (re.search(patt2,line) is None):
                line = line.strip()
                print line
        info.close()
        
    def pprobe_status(self):                                  #检查pprobe服务状态
        info = os.popen('service pprobe status')
        message = info.readlines()
        if message[0] == "nginx is running\n":
            self.color('nginx is running', 1)
        else:
            self.color('nginx is not running', 0)
        if message[1] == "php-fpm is running\n":
            self.color('php-fpm is running', 1)
        else:
            self.color('php-fpm is not running', 0)
        if message[2] == "mongod is running\n":
            self.color('mongod is running', 1)
        else:
            self.color('mongod is not running', 0)
        if message[3] == "alert_notify is running\n":
            self.color('alert_notify is running', 1)
        else:
            self.color('alert_notify is not running', 0)
        if message[4] == "pysocket is running\n":
            self.color('pysocket is running', 1)
        else:
            self.color('pysocket is not running', 0)
        if message[5] == "dfa_tcp is running\n":
            self.color('dfa_tcp is running', 1)
        else:
            self.color('dfa_tcp is not running', 0)
        if message[6] == "metad is running\n":
            self.color('metad is running', 1)
        else:
            self.color('metad is not running', 0)
        
        info.close()    
    def time_synchronization(self):
        self.color('Please make sure that your server time synchronized:',0)
        print 'you could excute command  \'ntpdate time.windows.com\' or \'ntpdate 133.100.11.8\'\
to synchronize time'

        over = '############################## \
Over, red information you should check carefully \
##############################'
        self.color(over, 2)
    

if __name__ == '__main__':
    
    iProbe = Enviroment()
    iProbe.os()
    iProbe.memory()
    iProbe.core()
    iProbe.numa()
    iProbe.probe()
    iProbe.iptables()
    iProbe.pprobe_status()
    iProbe.server_restart()
    
    iProbe.time_synchronization()
