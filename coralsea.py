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

    def clean(self):

