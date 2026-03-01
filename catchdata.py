import urllib.request

sender_ip = "x.x.x.x"          #Enter the IP address of the sender machine here
filename = "networkdata.txt"
port = 8080
 
url = f"http://{sender_ip}:{port}/{filename}"
urllib.request.urlretrieve(url, filename)
print(f"Downloaded: {filename}")