import os
import sys
import subprocess


def pcapng_to_pcap(pcapng_file):
    '''Converts a pcapng file to pcap for parsing. MUST have tshark installed.'''
    if not os.path.isfile(pcapng_file):
        print("{} is not a file".format(pcapng_file))
        sys.exit()
    if os.path.splitext(pcapng_file)[1].strip() != ".pcapng":
        print("{} is not a pcapng file".format(pcapng_file))
        sys.exit()
    command = ['tshark', '-F', 'pcap', '-r',
               pcapng_file, '-w', os.path.splitext(pcapng_file)[0] + '.pcap']
    subprocess.run(command, check=True)
            

#
# Main converts pcapng file at first commandline argument path to pcap
#
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python {} [pcap_file]".format(sys.argv[0]))
        sys.exit()
    pcapng_to_pcap(sys.argv[1])
    
