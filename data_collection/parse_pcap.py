from scapy.all import *
import pickle
import datetime
import sys
import os
import ipaddress
import netaddr
import numpy as np
import pandas as pd


def pcap_to_dict(pcap_file):
    '''Parses a pickle file into a list of dicts.

    Arguments:
      pcap_file: string filepath of pcap file

    Returns:
      List of dicts with one dict per packet in pcap file.
        The dicts have the following key/value pairs:
          "time"     : time the packet was receieved in seconds since epoch
          "datetime" : time the packet was received as a datetime object
          "length"   : length of packet in bytes
          "mac_src"  : source MAC address
          "mac_dst"  : destination MAC address
          "ip_src"   : source IP address
          "ip_dst"   : destination IP address
          "protocol" : 'TCP', 'UDP', 'ICMP', or None
          "port_src" : source port
          "port_dst" : destination port
          "is_dns"   : True if packet is DNS packet, else False
          "dns_query" : string DNS query
          "dns_resp" : string DNS response
    '''
    data = []
    with PcapReader(pcap_file) as pcap_reader:
        for i, pkt in enumerate(pcap_reader):
            pkt_dict = {}
            #if i % 1000 == 0 and i != 0: print(i)
            try:
                if Ether not in pkt:
                    continue
                
                pkt_dict["time"] = pkt.time
                pkt_dict["datetime"] = datetime.datetime.fromtimestamp(pkt.time)
                pkt_dict["length"] = len(pkt)
                pkt_dict["mac_dst"] = pkt[Ether].dst
                pkt_dict["mac_src"] = pkt[Ether].src
                pkt_dict["ip_dst"] = None
                pkt_dict["ip_src"] = None
                pkt_dict["protocol"] = None
                pkt_dict["port_dst"] = None
                pkt_dict["port_src"] =  None
                pkt_dict["is_dns"] = False
                pkt_dict["dns_query"] = None
                pkt_dict["dns_resp"] = None
                
                if IP in pkt:
                    pkt_dict["ip_dst"] = pkt[IP].dst
                    pkt_dict["ip_src"] = pkt[IP].src
                                
                if TCP in pkt:
                    pkt_dict["port_dst"] = pkt[TCP].dport
                    pkt_dict["port_src"] = pkt[TCP].sport
                    pkt_dict["protocol"] = 'TCP'
                elif UDP in pkt:
                    pkt_dict["port_dst"] = pkt[UDP].dport
                    pkt_dict["port_src"] = pkt[UDP].sport
                    pkt_dict["protocol"] = 'UDP'
                elif ICMP in pkt:
                    pkt_dict["protocol"] = 'ICMP'
                    
                if DNSQR in pkt:
                    pkt_dict["is_dns"] = True
                    pkt_dict["dns_query"] = pkt[DNSQR].qname
                if DNSRR in pkt:
                    pkt_dict["is_dns"] = True
                    pkt_dict["dns_resp"] = pkt[DNSRR].rrname
                
                data.append(pkt_dict)
            except:
                continue
    return data


def pcap_to_pandas(pcap_file):
    '''Parses pcap file into pandas DataFrame.

    Arguments:
        pcap_file: string filepath of pcap file

    Returns:
      DataFrame with one packet per row
        column names are the keys from pcap_to_dict plus
        'ip_dst_int', 'ip_src_int', 'mac_dst_int', 'mac_dst_int'
    '''
    data = pcap_to_dict(pcap_file)
    pd_data = pd.DataFrame(data)
    pd_data["datetime"] = pd_data["datetime"].apply(lambda x: np.datetime64(x))
    pd_data["datetime"] = pd.to_datetime(pd_data['datetime'])
    pd_data['ip_dst_int'] = pd_data['ip_dst'].apply(
        lambda x: None if x is None else int(ipaddress.ip_address(x)))
    pd_data['ip_src_int'] = pd_data['ip_src'].apply(
        lambda x: None if x is None else int(ipaddress.ip_address(x))) 
    pd_data["mac_dst_int"] = pd_data["mac_dst"].apply(
        lambda x: None if x is None else int(netaddr.EUI(x)))
    pd_data["mac_src_int"] = pd_data["mac_src"].apply(
        lambda x: None if x is None else int(netaddr.EUI(x)))
    pd_data["time_normed"] = pd_data["time"].apply(
        lambda x: x - pd_data.iloc[0]['time'])
    pd_data = pd_data.sort_index(axis=1)
    return pd_data

    
def parse_and_save_pcap(pcap_file, pickle_file):
    '''Parses pcap file and saves results as a compressed pickle file.

    Arguments:
      pcap_file: path of pcap file
      pickle_file: path to sae pickle file
    '''
    data = pcap_to_pandas(pcap_file)
    data.to_pickle(pickle_file)
    
        
def load_parsed_pcap(pickle_file):
    '''Reads already parsed pickle file back into memory.

    Arguments:
      pickle_file: path to pickle file saved by parse_and_save_pcap()
    
    Returns:
      pandas dataframe in the format created by pcap_to_pandas()
    '''
    data = pd.read_pickle(pickle_file)
    return data


def send_rates(data, window_len_sec):
    '''Calculates send rates from packet DataFrames

    Arguments:
      data: pandas DataFrame with 'time' and 'length' columns 
              like that returned from pcap_to_pandas()
      window_len_sec: interval for calculating rates

    Returns:
       rates: array of send rates
       times: array of times corresponding to each window in rates
    '''
    data = data.sort_values(by=["time"])
    windows = []
    times = []
    curr_time = data.iloc[0]["time"]
    end_time = curr_time + window_len_sec
    i = 0
    while curr_time < data.iloc[-1]["time"]:
        windows.append(0)
        times.append(curr_time)
        while i < len(data) and data.iloc[i]["time"] < end_time:
            windows[-1] += data.iloc[i]["length"]
            i += 1
        curr_time = end_time
        end_time = curr_time + window_len_sec
    rates = np.array(windows) / float(window_len_sec)
    times = np.array(times)
    return rates, times


#
# Main takes pcap filepath, parses and saves as pickle file.
#  Pickle filepath can be specified as second command line argument
#  or will default to the same path as the pcap file with .pkl extension
#
if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python {} [pcap_file] [pickle_file (optional)]".format(sys.argv[0]))
        sys.exit()
    pcap_file = sys.argv[1]
    if len(sys.argv) > 2:
        pickle_file = sys.argv[2]
    else:
        pickle_file = os.path.splitext(pcap_file)[0] + ".pkl"
    parse_and_save_pcap(pcap_file, pickle_file)
