from sys import stderr
import sys
import paramiko
user_name="vaibhav"
password="2469"
ip="172.20.253.132"
ssh_client=paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
ssh_client.connect(hostname=ip, username=user_name, password=password, timeout=50)
cmd="ls"
stdin, stdout, stderr = ssh_client.exec_command(cmd)
print("Started executing command on the remote server")
stdout=stdout.readlines()
sys.stdout = open('sshOutput.txt', 'w')
print("List of file present on the remote server's root folder: ")
print(stdout)
sys.stdout.close()
sftp_client = ssh_client.open_sftp()
sftp_client.get('/home/vaibhav/testfile.txt', 'paramiko_downloaded_file.txt')
sftp_client.close()
ssh_client.close()