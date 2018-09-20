#!/bin/python
import timeit
import threading
import hyper
import urllib
import collections
import time 
t_urlA=0
t_urlB=0
rate_A=0.0
rate_B=0.0
DOWNLOAD_CHUNK=1500
NUM_OF_DOWNLOADS=2
MAX_TRIALS=1
urlA="http://10.10.10.4/www-itec.uni-klu.ac.at/ftp/datasets/DASHDataset2014/BigBuckBunny/2sec/bunny_4219897bps/BigBuckBunny_2s180.m4s"
urlB="http://10.10.10.4/www-itec.uni-klu.ac.at/ftp/datasets/DASHDataset2014/BigBuckBunny/2sec/bunny_4219897bps/BigBuckBunny_2s180.m4s"
connection = hyper.HTTP20Connection('10.10.10.4', port=80, force_proto='h2', secure=False)
time_list=collections.OrderedDict()
rate_list=collections.OrderedDict()
def get_file(url1):
        #global t_urlA
        #global t_urlB
        #global rate_A
        #global rate_B
        parse_url = urllib.parse.urlparse(url1)
        segment_size=0
        t_start1=timeit.default_timer()
        http2_conn = connection.request('GET',parse_url.path)
        f_conn=connection.get_response(http2_conn)	
        '''
        f_data=f_conn.read(int(DOWNLOAD_CHUNK))
        while f_data: #<---
        	segment_size += len(f_data)
        	if (len(f_data) < DOWNLOAD_CHUNK):
            		break
        f_data = f_conn.read(int(DOWNLOAD_CHUNK)) #<--- reassign at the end to continue in the while loop 
        print ("GET_RESPONSE")
	'''
        segment_data = f_conn.read(DOWNLOAD_CHUNK)
        while segment_data:
                    segment_size+=len(segment_data)
                    if (len(segment_data) < DOWNLOAD_CHUNK):
                        break
                    segment_data = f_conn.read(DOWNLOAD_CHUNK)
        #f_data=f_conn.read()					      #	    till we have response data
        #end of how to use the API
        t_diff1=timeit.default_timer()-t_start1
        rate1=segment_size*8/t_diff1
        #f_conn.close()
        time_list[http2_conn]=t_diff1
        rate_list[http2_conn]=rate1
if __name__ == "__main__": 
 for x in range(0,MAX_TRIALS): 
  t_start1=timeit.default_timer()
  threads =[]
  try: 
     for i in range(0, NUM_OF_DOWNLOADS):
     	threads.append(threading.Thread(target=get_file,args=(urlA,)))
     	threads[i].start()
     for i in range(0, NUM_OF_DOWNLOADS):
        threads[i].join()
  except Exception as e:
     print ('[-] General Exception')
  connection.close()
  f_tot1=open("http2_tot_rate.csv","a")
  sorted_rate_list=sorted(rate_list.values(), reverse=True)
  print (sorted_rate_list)
  f_tot2=open("http2_tot_time.csv","a")
  sorted_time_list=sorted(time_list.values(), reverse=True)
  print (sorted_time_list)
  f_out=open("http2_get.csv","a")
  for item in rate_list.keys():
        f_out.write("%s,%s,%s\n"%(item,str(rate_list[item]),str(time_list[item])))
  f_tot1.write("%s\n"%sorted_rate_list[0])
  f_tot2.write("%s\n"%sorted_time_list[0])
f_out.close()
f_tot1.close()
f_tot2.close()
