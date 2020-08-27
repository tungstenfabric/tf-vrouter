import subprocess
import argparse
import os
import sys
import requests
from bs4 import BeautifulSoup
import urllib.request

# Global variable
RedHatOs = False
VRouterAgent = False
ControlNodeAgent = False
DPDKAgent = False
OPERATING_SYATEM_CENTOS = False
GDB_Flag = True
Docker_Copy_Stripped = False


#Change before running
your_location = '/root/CEM-1289/tf_debugger/'

#Change required
URL_STRIPPED ='/redhat70/newton/store/binaries/'

#Change only is the containerized version chnage
containerized_versions = ['1909','1910','1911','1912','2002','2005','2008']

#DO NOT CHANGE UNLESS REALLY NECESSARY
non_contaierized_link = 'http://10.84.5.100/cs-shared/github-build/'

debug_location_Unstripped = ":/usr/lib/debug/usr/bin/contrail-vrouter-agent.debug"

debug_location_Stripped = ':/usr/bin/'

URL = ['http://10.84.5.100/cs-shared/github-build/','/redhat70/newton/sandbox/build/debug/vnsw/agent/contrail/contrail-vrouter-agent','/redhat70/newton/sandbox/build/debug/control-node/contrail-control']

base_path = "svl-artifactory.juniper.net/contrail-nightly"




n = len(sys.argv)
p0=subprocess.run(['cat', '/etc/os-release'], stdout=subprocess.PIPE)
p1 = str(p0.stdout)
p2 =(p1.split("\\n")[0]).split("=")[1]

if('centos' in p1):
  OPERATING_SYATEM_CENTOS = True
else:
  if('redhat' in p1):
    OPERATING_SYATEM_CENTOS = False

def file_size(COMMAND_ARGUMENT):
  p1 = subprocess.check_output(['du','-sh', COMMAND_ARGUMENT]).split()[0].decode('utf-8')
  print("\nThe File Size is "+p1+"B,  program is running, hold on\n")

def core_info(commandLineArgument):
  core_file_name = commandLineArgument
  p2 = subprocess.run(['grep', '-a','-m', '2', 'build-info', core_file_name],stdout=subprocess.PIPE)
  p3 = str(p2.stdout)
  return p3


def Build_Version_ID_HOST_DPDK(p3):
  build_version_dpdk = None
  build_version_dpdk_idx = p3.find('"build-version":')
  if build_version_dpdk_idx != -1:
      x = p3[build_version_dpdk_idx:].find("}")
  build_version_dpdk = p3[build_version_dpdk_idx + 16:build_version_dpdk_idx + x]
  build_version_dpdk = build_version_dpdk.replace('"','')
  build_version_dpdk = build_version_dpdk.strip()
  build_host_dpdk = None
  build_host_dpdk_idx = p3.find('"build-hostname":')
  if build_host_dpdk_idx != -1:
      x = p3[build_host_dpdk_idx:].find(",")
  build_host_dpdk = p3[build_host_dpdk_idx + 17:build_host_dpdk_idx + x]
  build_host_dpdk = build_host_dpdk.replace('"','')
  build_id_dpdk = build_host_dpdk.split("centos-")
  build_id_dpdk = build_id_dpdk[1].split("-")[0]
  return(build_version_dpdk,build_host_dpdk,build_id_dpdk)

def Build_ID(p3):
  build_id = None
  build_id_idx = p3.find('"build-id":')
  if build_id_idx != -1:
      x = p3[build_id_idx:].find(",")
  build_id = p3[build_id_idx + 11:build_id_idx + x]
  build_id = build_id.replace('"','')
  return build_id

def Build_Version(build_id):
  build_version_number = build_id.split("-") [0]
  build_id_version =((build_id.split("-") [1]).split(".")[0])
  finding_length =  len(build_version_number)-1
  usable_version_number = build_version_number[:finding_length]

  return (build_version_number, build_id_version, usable_version_number)

def Build_Time(p3):
  build_time = None
  build_time_idx = p3.find('"build-time":')
  if build_time_idx != -1:
    x = p3[build_time_idx:].find(",")
  build_time = p3[build_time_idx + 13:build_time_idx + x]
  return build_time

def Build_Host(p3):
  build_host_name = None
  build_host_idx = p3.find('"build-hostname":')
  if build_host_idx != -1:
    x = p3[build_host_idx:].find(",")
  build_host_name = p3[build_host_idx + 17:build_host_idx + x]
  build_host_name = build_host_name.replace('"','')
  return build_host_name

def WhereIsMyDocker(Hostname, BuildVersion, IDVersion):
  global RedHatOs
  build_host_name = Hostname
  build_version_number = BuildVersion
  build_id_version = IDVersion
  if ('centos' in build_host_name ):
    if(OPERATING_SYATEM_CENTOS):
      RedHatOs = False
  else:
    if('redhat' in build_host_name ):
      if(not OPERATING_SYATEM_CENTOS):
        RedHatOs = True
      else:
        print("The operating system you are on is "+p2+" and this is a gcore which was not generated on the same opeating system, please run the script on appropriate operaring system to get the right results \n")
        sys.exit()

  if (BuildVersion == '1910'):
    if (RedHatOs):
      if(ControlNodeAgent):
        docker_path = base_path+"/contrail-debug:"+build_version_number+"-"+build_id_version+'-rhel'
        docker_path_stripped = base_path+"/contrail-controller-control-control:"+build_version_number+"-"+build_id_version+'-rhel'
      elif(DPDKAgent):
        docker_path = base_path+"/contrail-debug:"+build_version_number+"-"+build_id_version+'-rhel'
        docker_path_stripped = base_path+"/contrail-vrouter-agent-dpdk:"+build_version_number+"-"+build_id_version+'-rhel'
      else:
        docker_path = base_path+"/contrail-debug:"+build_version_number+"-"+build_id_version+'-rhel'
        docker_path_stripped = base_path+"/contrail-vrouter-agent:"+build_version_number+"-"+build_id_version+'-rhel'
    else:
      if(ControlNodeAgent):
        docker_path = base_path+"/contrail-debug:"+build_version_number+"-"+build_id_version
        docker_path_stripped = base_path+"/contrail-controller-control-control:"+build_version_number+"-"+build_id_version
      elif(DPDKAgent):
        docker_path = base_path+"/contrail-debug:"+build_version_number+"-"+build_id_version
        docker_path_stripped = base_path+"/contrail-vrouter-agent-dpdk:"+build_version_number+"-"+build_id_version
      else:
        docker_path = base_path+"/contrail-debug:"+build_version_number+"-"+build_id_version
        docker_path_stripped = base_path+"/contrail-vrouter-agent:"+build_version_number+"-"+build_id_version
  else:
    if (RedHatOs):
      if(ControlNodeAgent):
        docker_path = base_path+"/contrail-debug:"+build_version_number+"."+build_id_version+'-rhel'
        docker_path_stripped = base_path+"/contrail-controller-control-control:"+build_version_number+"."+build_id_version+'-rhel'
      elif(DPDKAgent):
        docker_path = base_path+"/contrail-debug:"+build_version_number+"."+build_id_version+'-rhel'
        docker_path_stripped = base_path+"/contrail-vrouter-agent-dpdk:"+build_version_number+"."+build_id_version+'-rhel'
      else:
        docker_path = base_path+"/contrail-debug:"+build_version_number+"."+build_id_version+'-rhel'
        docker_path_stripped = base_path+"/contrail-vrouter-agent:"+build_version_number+"."+build_id_version+'-rhel'
    else:
      if(ControlNodeAgent):
        docker_path = base_path+"/contrail-debug:"+build_version_number+"."+build_id_version
        docker_path_stripped = base_path+"/contrail-controller-control-control:"+build_version_number+"."+build_id_version
      elif(DPDKAgent):
        docker_path = base_path+"/contrail-debug:"+build_version_number+"."+build_id_version
        docker_path_stripped = base_path+"/contrail-vrouter-agent-dpdk:"+build_version_number+"."+build_id_version
      else:
        docker_path = base_path+"/contrail-debug:"+build_version_number+"."+build_id_version
        docker_path_stripped = base_path+"/contrail-vrouter-agent:"+build_version_number+"."+build_id_version
  return(docker_path, docker_path_stripped)





def GenerateURl(build_version_number):
  p = []
  x = ''
  y = 0
  max_length = 0
  final_string = ''
  version = build_version_number
  alink = non_contaierized_link
  f = urllib.request.urlopen(alink)
  myfile = f.read()
  soup = BeautifulSoup(myfile, 'html.parser')
  for link in soup.find_all('a'):
    p.append(link.get('href'))
  p = p[5:23]
  for list_number in range(len(p)):
    str_short = min(len(p[list_number]), len(version))
    for i in range(str_short):
      if (version[i] == p[list_number][i]):
        if ( max_length < i):
          max_length = i
          final_string = version[:max_length +1]
      else:
        break
  if(final_string.endswith(".") and (final_string[:-1]+'/') in p):
      final_string = final_string[:-1]
      final_string = final_string+"/"
  elif(final_string+"x/" in p):
      final_string = final_string+"x/"
  elif(final_string+"/" in p):
      final_string = final_string+"/"
  else:
      print("couldnt find version "+""+ version)
      sys.exit()

  return final_string



def DockerCopy(build_version_number,build_id_version,PathOfTheDocker, NameOfTheFile, BinaryLocation):
  docker_path = PathOfTheDocker
  file_name = NameOfTheFile
  debug_location = BinaryLocation

  print("fetching from the docker...")
  p10 = subprocess.run(['docker','pull', docker_path])
  p13  = subprocess.run(['docker','images', docker_path,'--format','"{{.ID}}"'], stdout=subprocess.PIPE)
  p13 = p13.stdout
  docker_ID_list = p13.decode("UTF-8").replace('"','').splitlines()
  print("docker Image ID:  "+docker_ID_list[0])
  p14 = subprocess.run(['docker','run', "-d", docker_ID_list[0]])
  p12 = subprocess.run(['docker','ps','-a', '--format','"{{.Names}}"'], stdout=subprocess.PIPE )
  p12 = p12.stdout
  docker_names_list = p12.decode("UTF-8").splitlines()
  for i in range(len(docker_names_list)):
      docker_names_list[i] = docker_names_list[i].replace('"','')
  print("docker-name:  "+ docker_names_list[0])
  creating_new_directory_path = subprocess.run(['mkdir',your_location+build_id_version+"_"+build_version_number],stdout=subprocess.PIPE)
  if(not Docker_Copy_Stripped):
        copier = subprocess.run(['docker','cp',docker_names_list[0] + debug_location ,your_location+build_id_version+"_"+build_version_number+"/"+file_name])
  else:
    if (ControlNodeAgent):
        copier = subprocess.run(['docker','cp',docker_names_list[0] + debug_location+"contrail-control", your_location+build_id_version+"_"+build_version_number+"/"+file_name])
    else:
        copier = subprocess.run(['docker','cp',docker_names_list[0] + debug_location+"contrail-vrouter-agent" ,your_location+build_id_version+"_"+build_version_number+"/"+file_name])



def binary_get(BuildVersion, IDVersion,PathOfTheDocker, PathOfTheDockerStripped ):
  build_version_number = BuildVersion
  build_id_version = IDVersion
  docker_path_unstripped = PathOfTheDocker
  docker_path_stripped = PathOfTheDockerStripped
  file_name_Unstripped = "contrail-vrouter-agent.debug"
  file_name_Stripped = "contrail-vrouter-agent-stripped"
  global Docker_Copy_Stripped


  if(build_version_number in containerized_versions):
    DockerCopy(build_version_number,build_id_version,docker_path_unstripped, file_name_Unstripped, debug_location_Unstripped)
    Docker_Copy_Stripped = True
    DockerCopy(build_version_number,build_id_version,docker_path_stripped, file_name_Stripped, debug_location_Stripped)

  else:
    creating_new_directory_path = subprocess.run(['mkdir',your_location+build_id_version+"_"+build_version_number],stdout=subprocess.PIPE)
    version ="R"+build_version_number
    if (VRouterAgent or DPDKAgent):
        usable_version_number = GenerateURl(version)
        file_url_unstripped = URL[0]+usable_version_number+build_id_version+URL[1]
        file_url_stripped = URL[0]+usable_version_number+build_id_version+URL_STRIPPED+'contrail-vrouter-agent'
    else:
        usable_version_number = GenerateURl(version)
        file_url_unstripped = URL[0]+usable_version_number+build_id_version+URL[2]
        file_url_stripped = URL[0]+usable_version_number+build_id_version+URL_STRIPPED+'contrail-control'
    file_object = requests.get(file_url_unstripped)
    with open( your_location+build_id_version+"_"+build_version_number+'/contrail-vrouter-agent.debug', 'wb') as local_file:
        local_file.write(file_object.content)
    file_object = requests.get(file_url_stripped)
    with open(your_location+build_id_version+"_"+build_version_number+'/contrail-vrouter-agent-stripped', 'wb') as local_file:
        local_file.write(file_object.content)

def Running_GDB_Custom(ID, VERSION, core_file_name, GdbScript):
  build_id_version = ID
  build_version_number = VERSION
  core_file_name = core_file_name
  copier = GdbScript
  GDBLogNamer = os.path.basename(sys.argv[1])
  
  fin = open(copier)
  fout = open("Buffered_GDB_output.txt", "wt")
  fout.write("core "+your_location+core_file_name+"\nfile contrail-vrouter-agent-stripped\nsymbol-file contrail-vrouter-agent.debug\n")
  for line in fin:
    if 'set logging file' in line:
      fout.write('set logging file '+GDBLogNamer+'_GDB.log\n')
    else:
      fout.write(line)
  fin.close()
  fout.close()

  move = subprocess.run(['cp', core_file_name, your_location+build_id_version+"_"+build_version_number+"/" ], stdout=subprocess.PIPE)
  move_GDB_script = subprocess.run(['cp', "Buffered_GDB_output.txt", your_location+build_id_version+"_"+build_version_number+"/" ], stdout=subprocess.PIPE)
  change_dir = subprocess.run(['cd',build_id_version+"_"+build_version_number], shell=True)
  pwd = subprocess.run(['pwd'],cwd= your_location+build_id_version+"_"+build_version_number, stdout=subprocess.PIPE)
  running_GDB = subprocess.run(['gdb' ,'-x', 'Buffered_GDB_output.txt'], cwd= your_location+build_id_version+"_"+build_version_number, stdout=subprocess.PIPE)

def Running_GDB(ID, VERSION, core_file_name):
  build_id_version = ID
  build_version_number = VERSION
  core_file_name = core_file_name
  GDBLogNamer = os.path.basename(sys.argv[1])

  fin = open("default_GDB_commands.txt")
  fout = open("Buffered_GDB_output.txt", "wt")
  fout.write("core "+core_file_name+"\nfile contrail-vrouter-agent-stripped\nsymbol-file contrail-vrouter-agent.debug\n")
  for line in fin:
    if 'set logging file' in line:
      fout.write('set logging file '+GDBLogNamer+'_GDB.log\n')
    else:
      fout.write(line)
  fin.close()
  fout.close()
  move = subprocess.run(['cp', core_file_name, your_location+build_id_version+"_"+build_version_number+"/" ], stdout=subprocess.PIPE)
  move_GDB_script = subprocess.run(['cp', "Buffered_GDB_output.txt", your_location+build_id_version+"_"+build_version_number+"/" ], stdout=subprocess.PIPE)
  change_dir = subprocess.run(['cd',build_id_version+"_"+build_version_number], shell=True)
  pwd = subprocess.run(['pwd'],cwd= your_location+build_id_version+"_"+build_version_number, stdout=subprocess.PIPE)
  running_GDB = subprocess.run(['gdb' ,'-x', 'Buffered_GDB_output.txt'], cwd= your_location+build_id_version+"_"+build_version_number, stdout=subprocess.PIPE)

def Calling_for_help():
  print("\nTUNGSTEN FABRIC CORE ANALYZER USAGE\n[SCRIPT][CORE FILE] -- for C++ module\n[SCRIPT][CORE FILE][-f][VERSION NUMBER][ID NUMBER] -- to override and feed in the version and the id manually\n[SCRIPT][CORE FILE][-gdb] -- to pass a custom gdb file\n[SCRIPT][-h] -- for help\n[SCRIPT][CORE FILE][-f][VERSION NUMBER][ID NUMBER][-gdb][GDB_SCRIPT.TXT] -- to override the version and the id manually and to pass a custom gdb script to run\n")

def Summary(VERSION,ID, HOST, TIME, AGENT):
  print("\nSUMMARY---\nAGENT :"+AGENT+"\nVERSION fo the GCORE :"+VERSION+"\nThe ID from the GCORE :"+ID+"\nThe HOST-NAME :"+HOST+"\nThe BUILD_TIME :"+TIME+"\nThe GDB output log file is stored in the directory :"+ID+"_"+VERSION+"\nChange directory to view the GDB log file\n")

def Vrouter(COMMAND_ARGUMENT):
  file_size(COMMAND_ARGUMENT)
  AGENT = 'VROUTER AGENT'
  global VRouterAgent
  VRouterAgent = True
  COMMAND_ARGUMENT = sys.argv[1]
  FILE_INFO = core_info(COMMAND_ARGUMENT)
  print("fetching info....................\n\n")
  FULL_ID = Build_ID(FILE_INFO)
  VERSION, ID, USABLE_VERSION = Build_Version(FULL_ID)
  TIME = Build_Time(FILE_INFO)
  HOST = Build_Host(FILE_INFO)
  DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED = WhereIsMyDocker(HOST, VERSION, ID )
  binary_get(VERSION, ID, DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED)
  print("\n\nRunning GDB...\n\n")
  return VERSION, ID, TIME, HOST, AGENT


def DPDK(COMMAND_ARGUMENT):
  AGENT ="DPDK CORE"
  global DPDKAgent
  DPDKAgent = True
  COMMAND_ARGUMENT = sys.argv[1]
  print("fetching info....................")
  FILE_INFO = core_info(COMMAND_ARGUMENT) 
  VERSION, HOST, ID = Build_Version_ID_HOST_DPDK(FILE_INFO)
  TIME = Build_Time(FILE_INFO)
  DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED = WhereIsMyDocker(HOST, VERSION, ID )
  print("\n\nRunning GDB...\n\n")
  binary_get(VERSION, ID, DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED)

  return VERSION, ID, TIME, HOST, AGENT

def ControlNode(COMMAND_ARGUMENT):
  file_size(COMMAND_ARGUMENT)
  AGENT="CONTROL_NODE CORE"
  global ControlNodeAgent
  ControlNodeAgent = True
  COMMAND_ARGUMENT = sys.argv[1]
  print("fetching info....................")
  FILE_INFO = core_info(COMMAND_ARGUMENT)
  FULL_ID = Build_ID(FILE_INFO)
  VERSION, ID, USABLE_VERSION = Build_Version(FULL_ID)
  TIME = Build_Time(FILE_INFO)
  HOST = Build_Host(FILE_INFO)
  DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED = WhereIsMyDocker(HOST, VERSION, ID)
  binary_get(VERSION, ID, DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED)
  print("\n\nRunning GDB...\n\n")

  return VERSION, ID, TIME, HOST, AGENT

def main():

    n = len(sys.argv)
    COMMAND_ARGUMENT = sys.argv[1]
    Agent_name = subprocess.run(['file', COMMAND_ARGUMENT], stdout=subprocess.PIPE)
    Agent_name= str(Agent_name.stdout)

    if(n ==1 and (COMMAND_ARGUMENT == '--help' or COMMAND_ARGUMENT == '-h')):
      Calling_for_help()
      sys.exit()

    elif((("vrouter-agent") in Agent_name) and n == 2):
      print("running Vrouter program")
      VERSION, ID, TIME, HOST, AGENT = Vrouter(COMMAND_ARGUMENT)
      CALLING_GDB = Running_GDB(ID, VERSION, COMMAND_ARGUMENT)
      Summary(VERSION,ID, HOST, TIME, AGENT)

    elif((("contrail-vrouter-dpdk") in Agent_name) and n == 2):
      print("running DPDK program")
      VERSION, ID, TIME, HOST, AGENT = DPDK(COMMAND_ARGUMENT)
      CALLING_GDB = Running_GDB(ID, VERSION, COMMAND_ARGUMENT)
      Summary(VERSION,ID, HOST, TIME, AGENT)
       
    elif(("contrail-control") in Agent_name and n == 2):
      print("running ControlNode program")
      VERSION, ID, TIME, HOST, AGENT = ControlNode(COMMAND_ARGUMENT)
      CALLING_GDB = Running_GDB(ID, VERSION, COMMAND_ARGUMENT)
      Summary(VERSION,ID, HOST, TIME, AGENT)

    elif( n == 4 and sys.argv[2] == '-gdb'):
      print("in condition GDB")
      GDBSCRIPT = sys.argv[3]

      if((("vrouter-agent") in Agent_name)):
        print("running Vrouter program")
        VERSION, ID, TIME, HOST, AGENT = Vrouter(COMMAND_ARGUMENT)
        CALLING_GDB = Running_GDB_Custom(ID, VERSION, COMMAND_ARGUMENT, GDBSCRIPT)
        Summary(VERSION,ID, HOST, TIME, AGENT)

      elif((("contrail-vrouter-dpdk") in Agent_name)):
        print("running DPDK program")
        VERSION, ID, TIME, HOST, AGENT = DPDK(COMMAND_ARGUMENT)
        CALLING_GDB = Running_GDB_Custom(ID, VERSION, COMMAND_ARGUMENT, GDBSCRIPT)
        Summary(VERSION,ID, HOST, TIME, AGENT)

      elif(("contrail-control") in Agent_name):
        print("running ControlNode program")
        VERSION, ID, TIME, HOST, AGENT = ControlNode(COMMAND_ARGUMENT)
        CALLING_GDB = Running_GDB_Custom(ID, VERSION, COMMAND_ARGUMENT, GDBSCRIPT)
        Summary(VERSION,ID, HOST, TIME, AGENT)

    elif(n == 5 and sys.argv[2] == '-f'):
      VERSION_BY_USER= sys.argv[3]
      ID_BY_USER = sys.argv[4]


      if((("vrouter-agent") in Agent_name)):
        print("inside GDB vrouter")
        file_size(COMMAND_ARGUMENT)
        AGENT = 'VROUTER AGENT'
        print("\nOverride\n")
        COMMAND_ARGUMENT = sys.argv[1]
        FILE_INFO = core_info(COMMAND_ARGUMENT)
        FULL_ID = Build_ID(FILE_INFO)
        VERSION, ID, USABLE_VERSION = Build_Version(FULL_ID)
        TIME = Build_Time(FILE_INFO)
        HOST = Build_Host(FILE_INFO)
        DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED = WhereIsMyDocker(HOST, VERSION_BY_USER, ID_BY_USER )
        binary_get(VERSION_BY_USER, ID_BY_USER, DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED)
        print("\n\nRunning GDB...\n\n")
        CALLING_GDB = Running_GDB(ID_BY_USER, VERSION_BY_USER, COMMAND_ARGUMENT)
        Summary(VERSION_BY_USER,ID_BY_USER, HOST, TIME, AGENT)

      elif((("contrail-vrouter-dpdk") in Agent_name)):
        print("inside GDB dpdk")
        file_size(COMMAND_ARGUMENT)
        AGENT ="DPDK CORE"
        global DPDKAgent
        DPDKAgent = True
        COMMAND_ARGUMENT = sys.argv[1]
        print("fetching info....................")
        FILE_INFO = core_info(COMMAND_ARGUMENT)
        VERSION, HOST, ID = Build_Version_ID_HOST_DPDK(FILE_INFO)
        TIME = Build_Time(FILE_INFO)
        DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED = WhereIsMyDocker(HOST, VERSION_BY_USER, ID_BY_USER )
        print("\n\nRunning GDB...\n\n")
        binary_get(VERSION_BY_USER, ID_BY_USER, DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED)
        print("\n\nRunning GDB...\n\n")
        CALLING_GDB = Running_GDB(ID_BY_USER, VERSION_BY_USER, COMMAND_ARGUMENT)
        Summary(VERSION_BY_USER,ID_BY_USER, HOST, TIME, AGENT)

      elif(("contrail-control") in Agent_name):
        print("inside GDB control-node")
        file_size(COMMAND_ARGUMENT)
        AGENT="CONTROL_NODE CORE"
        global ControlNodeAgent
        ControlNodeAgent = True
        COMMAND_ARGUMENT = sys.argv[1]
        print("fetching info....................")
        FILE_INFO = core_info(COMMAND_ARGUMENT)
        FULL_ID = Build_ID(FILE_INFO)
        VERSION, ID, USABLE_VERSION = Build_Version(FULL_ID)
        TIME = Build_Time(FILE_INFO)
        HOST = Build_Host(FILE_INFO)
        DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED = WhereIsMyDocker(HOST, VERSION_BY_USER, ID_BY_USER )
        binary_get(VERSION_BY_USER, ID_BY_USER, DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED)
        print("\n\nRunning GDB...\n\n")
        VERSION, ID, TIME, HOST, AGENT = ControlNode(COMMAND_ARGUMENT)
        CALLING_GDB = Running_GDB(ID_BY_USER, VERSION_BY_USER, COMMAND_ARGUMENT)
        Summary(VERSION_BY_USER,ID_BY_USER, HOST, TIME, AGENT)


    elif(n == 7 and sys.argv[2] == '-f' and sys.argv[5] == '-gdb'):
      VERSION_BY_USER= sys.argv[3]
      ID_BY_USER = sys.argv[4]
      GDBSCRIPT = sys.argv[6]

      if((("vrouter-agent") in Agent_name)):
        print("inside GDB vrouter")
        file_size(COMMAND_ARGUMENT)
        AGENT = 'VROUTER AGENT'
        print("\nOverride\n")
        COMMAND_ARGUMENT = sys.argv[1]
        FILE_INFO = core_info(COMMAND_ARGUMENT)
        FULL_ID = Build_ID(FILE_INFO)
        VERSION, ID, USABLE_VERSION = Build_Version(FULL_ID)
        TIME = Build_Time(FILE_INFO)
        HOST = Build_Host(FILE_INFO)
        DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED = WhereIsMyDocker(HOST, VERSION_BY_USER, ID_BY_USER )
        binary_get(VERSION_BY_USER, ID_BY_USER, DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED)
        print("\n\nRunning GDB...\n\n")
        CALLING_GDB = Running_GDB_Custom(ID, VERSION, COMMAND_ARGUMENT, GDBSCRIPT)
        Summary(VERSION_BY_USER,ID_BY_USER, HOST, TIME, AGENT)

      elif((("contrail-vrouter-dpdk") in Agent_name)):
        print("inside GDB and -f dpdk")
        file_size(COMMAND_ARGUMENT)
        AGENT ="DPDK CORE"
        DPDKAgent = True
        print(DPDKAgent)
        COMMAND_ARGUMENT = sys.argv[1]
        print("fetching info....................")
        FILE_INFO = core_info(COMMAND_ARGUMENT)
        VERSION, HOST, ID = Build_Version_ID_HOST_DPDK(FILE_INFO)
        TIME = Build_Time(FILE_INFO)
        DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED = WhereIsMyDocker(HOST, VERSION_BY_USER, ID_BY_USER )
        print("\n\nRunning GDB...\n\n")
        binary_get(VERSION_BY_USER, ID_BY_USER, DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED)
        print("\n\nRunning GDB...\n\n")
        CALLING_GDB = Running_GDB(ID_BY_USER, VERSION_BY_USER, COMMAND_ARGUMENT)
        Summary(VERSION_BY_USER,ID_BY_USER, HOST, TIME, AGENT)

      elif(("contrail-control") in Agent_name):
        print("inside GDB control-node")
        file_size(COMMAND_ARGUMENT)
        AGENT="CONTROL_NODE CORE"
        ControlNodeAgent = True
        COMMAND_ARGUMENT = sys.argv[1]
        print("fetching info....................")
        FILE_INFO = core_info(COMMAND_ARGUMENT)
        FULL_ID = Build_ID(FILE_INFO)
        VERSION, ID, USABLE_VERSION = Build_Version(FULL_ID)
        TIME = Build_Time(FILE_INFO)
        HOST = Build_Host(FILE_INFO)
        DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED = WhereIsMyDocker(HOST, VERSION_BY_USER, ID_BY_USER )
        binary_get(VERSION_BY_USER, ID_BY_USER, DOCKER_PATH_UNSTRIPPED, DOCKER_PATH_STRIPPED)
        print("\n\nRunning GDB...\n\n")
        VERSION, ID, TIME, HOST, AGENT = ControlNode(COMMAND_ARGUMENT)
        CALLING_GDB = Running_GDB_Custom(ID, VERSION, COMMAND_ARGUMENT, GDBSCRIPT)
        Summary(VERSION_BY_USER,ID_BY_USER, HOST, TIME, AGENT)

    elif(n==2 and (sys.argv[1]== '-h')):
      Calling_for_help()
      sys.exit()

    else:
      Calling_for_help()
      sys.exit()



if __name__=="__main__":
    main()
