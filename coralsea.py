#!/usr/bin/env python
# coding:utf-8 
   def step8(self):
        log.info('Calculate the percentage')
        cluster = (float(self.cluster_count)/float(self.forword))*100
        self.cluster_detect_precent = round(cluster,3)
        distinct1 = (float(self.distinct_id_num)/float(self.url))*100
        self.distinct_id_precent = round(distinct1,3)        
        return Testcase.PASS         

    def clean(self):

        log.info('Calculate the percentage')
        cluster = (float(self.cluster_count)/float(self.forword))*100
        self.cluster_detect_precent = round(cluster,3)
        distinct1 = (float(self.distinct_id_num)/float(self.url))*100
        self.distinct_id_precent = round(distinct1,3)        
        return Testcase.PASS 
