#!/usr/bin/env python
# coding:utf-8 
   def step8(self):
        log.info('Calculate the percentage')
        cluster = (float(self.cluster_count)/float(self.forword))*100
        self.cluster_detect_precent = round(cluster,3)
        uri = (float(self.uri_count)/float(self.uri_origin_n))*100
        self.uri_detect_precent = round(uri,3)
        host = (float(self.host_count)/float(self.host_origin_n))*100
        self.host_detect_precent= round(host,3)
        ua = (float(self.ua_count)/float(self.ua_origin_n))*100
        self.ua_detect_precent = round(ua,3)
        distinct = (float(self.distinct_family_number)/float(self.url))*100
        self.distinct_precent = round(distinct,3)
        distinct1 = (float(self.distinct_id_num)/float(self.url))*100
        self.distinct_id_precent = round(distinct1,3)        
        return Testcase.PASS         
    def step9(self):
        log.info('output result')
        os_ver = self.os_version
        sig_ver = self.sig_version
        pass_flag = self.sig_path + sig_ver + ".atd_pass"
        f = open(pass_flag,'w+')
        f.write('')
        f.close()
        self.mailto_list = ['sju@hillstonenet.com']
        self.mailto_sju=['sju@hillstonenet.com']
        self.subject = "Coral sea Test"
        self.attachment = ''
        title = "<b>CoralSea ATD detect result version: %s sig_version: %s</b>" %(self.os_version,self.sig_version)
        body = "Total: %s<br>\nURL: %s<br>\nFamily: %s<br>\nDistinct_count: %s<br>\nDistinct_num_by_id: %s<br>\n" %(self.total, self.url, self.family, self.distinct_family_number,self.distinct_id_num)
        body = body + "Cluster_count: %s<br>\nForword: %s<br>\nHost_origin_n: %s<br>\nHost_count: %s<br>\n" %(self.cluster_count, self.forword, self.host_origin_n,self.host_count)
        body = body + "Uri_origin_n: %s<br>\nUri_count: %s<br>\nUa_origin_n: %s<br>\nUa_count: %s<br>\nDistinct_precent: %s<br>\nDistinct_by_id:%s<br>\n"%(self.uri_origin_n, self.uri_count, self.ua_origin_n, self.ua_count, self.distinct_precent,self.distinct_id_precent)
        body = body + "Cluster_detect_precent: %s<br>\n Uri_detect_precent: %s<br>\nHost_detect_precent: %s<br>\n Ua_detect_precent: %s" %(self.cluster_detect_precent,self.uri_detect_precent,self.host_detect_precent,self.ua_detect_precent) 
        self.content = "<html><head><p>%s</p></head><body>%s</body></html>\n" %(title,body)
        send_Mail(self)
        return Testcase.PASS      
    def step10(self):
        log.info("host pcap collecting")
        m = "threat"
        hostlist = []
        f = file("/tmp/know_file_5_2")
        n = file("/tmp/host.txt", "w+")
        rslt = self.pc1.cmd('rm /tmp/*.pcap')
        print "1111111111111111111111111111111111111111111111111111111111111111111"
        rslt = self.dut1.config('clear logging threat')
        if rslt:
            log.error('Clear logging threat failed!rslt is:%s' % rslt)
            return Testcase.FAIL
        number = f.readline()
        for line in f:
            if (not line.strip().startswith('#')) or ( ':' not in line) :
                hostpcap = line.strip().split(':')[0]
                rslt = self.dut1.config('clear logging threat')
                rslt = self.pc1.cmd('cd /tmp/&& python collecthost.py %s' %hostpcap)
                rslt = self.pc1.cmd('cd /tmp&&/tmp/tcpreplay_2_2portdut4.sh', timeout = 10)
                rslt = self.dut1.config('show logging threat')
            j = re.search(m,rslt)
            if j is not None:
                hostlist.append(line)
                if len(hostlist) == 11:
                    break
            else:
                pass
        n.writelines(hostlist)
        f.close()
        n.close()
        rslt = self.pc1.cmd('rm /tmp/*.pcap') 
        rslt = self.pc1.cmd('cd /tmp&&python /tmp/host.py host.txt', timeout = 200)
        if not rslt: 
            log.error('config failed')
            return Testcase.FAIL
        rslt = self.pc1.cmd('cd /tmp&& tar -cf pcap.tar *.pcap')
        mailto_sju=["sju@hillstonenet.com","lmqin@Hillstonenet.com"]
        self.mailto_list = mailto_sju
        self.subject = 'detect pcap'
        self.attachment = ['/tmp/pcap.tar']
        title = "<b>CoralSea ATD detect result version: %s sig_version: %s</b>" %(self.os_version,self.sig_version)
        self.content = "<html><head><p>%s</p></head><body><p>hi,all this is test pcap by host</p></body></html>\n" %title
        rslt = send_Mail(self)
        return 0
        return Testcase.PASS
    def clean(self):
        """Some house cleaning"""
        rslt = self.pc1.cmd('rm /tmp/report.txt')       
        if  rslt:
            log.error('config failed')
            return Testcase.FAIL
        log.info('clean sql count')
#        os.remove(self.running_flag)
        rslt = self.dut1.sql(database = "utad_db", cmd="delete from malware_report_tbl;")
        if not rslt:
            print "sql unsuccessfully"
            return Testcase.FAIL
        return Testcase.PASS

