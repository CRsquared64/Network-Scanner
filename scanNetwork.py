import socket
import os
from ping3 import ping
import numpy as np
from multiprocessing import Process, Queue



class ScanNetwork:
    def __init__(self, ipmin=1, ipmax=255):
        self.ipmin = ipmin
        self.ipmax = ipmax

        self.parts = 16
        self.active = []
        self.active_queue = Queue()

    def ip_gen(self):
        ips = []
        i = 0
        column = self.ipmin
        while True:
            i += 1
            if i == 255:
                column = column + 1
                i = 0
            elif column == self.ipmax + 1:
                break

            ips.append(f"192.168.{column}.{i}")
            # print(f"192.168.{column}.{i}")

        return ips

    def check_active(self, ips):
        active_ips = []
        for ip in ips:
            res = ping(ip)
            if res:
                active_ips.append(ip)
                print(ip)
        self.active_queue.put(active_ips)

    def snoop(self):
        for ip in self.active:
            index = self.active.index(ip)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"[{index}] {ip}: {hostname}")
            except socket.herror:
                 print(f"[{index}] {ip}: Null")
    def inital_port(self, ip):
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3389, 5900, 8080]
        print("\n Starting Common Ports Scanning... \n")
        for port in common_ports:
            scan = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dest = (f"{ip}", port)
            check = scan.connect_ex(dest)
            if check == 0:
                print(f"{port}: Port Open")
            else:
                print(f"{port}: Port Closed")
            scan.close()


    def __call__(self, *args, **kwargs):
        ips = self.ip_gen()
        # print(len(ips))
        ips = np.array_split(ips, self.parts)
        processes = []
        for i in range(self.parts):
            # print(ips[i])
            p = Process(target=self.check_active, args=(ips[i],))
            p.start()
            processes.append(p)
        for p in processes:
            p.join()
        while not self.active_queue.empty():
            self.active.extend(self.active_queue.get())

        print(self.active)
        print("\n Starting IP snoop... \n")
        self.snoop()

        print("\n Select Index Of IP to examine: ")
        while True:
            inp = int(input())
            if inp > 0 & inp <= len(self.active):
                selected = self.active[inp]
                print(f"Selected: {selected}")
                break
            else:
                print(inp + "Not in range")
        self.inital_port(selected)


        # active = self.check_active(ips)


if __name__ == "__main__":
    run = ScanNetwork(0, 1)
    run()
