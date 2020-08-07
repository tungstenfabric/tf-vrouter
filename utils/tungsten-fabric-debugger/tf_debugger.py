import subprocess
import argparse
import sys
import requests


RedHatOs = False
VRouterAgent = True
GDB_Flag = True

URL = ['http://10.84.5.100/cs-shared/github-build/R', 'x/', '/redhat70/newton/sandbox/build/debug/vnsw/agent/contrail/contrail-vrouter-agent', '/redhat70/newton/sandbox/build/debug/control-node/contrail-control']
base_path_Vrouter = "svl-artifactory.juniper.net/contrail-nightly/contrail-debug:"
Production_Binary = '/root/CEM-1289/tf_debugger/contrail-vrouter-agent'
containerized_versions = ['1909','1910','1911','1912','2002','2005','2008']

n = len(sys.argv)

#defining the functions here
def core_info(commandLineArgument):
  core_file_name = commandLineArgument
  p1 = subprocess.run(['strings', core_file_name], stdout=subprocess.PIPE)
  p2 = subprocess.run(['grep', '-n', 'build-version'],stdout=subprocess.PIPE, input=p1.stdout)
  p3 = str(p2)
  return p3

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
  print( "build-version:"+ build_version_number)
  finding_length =  len(build_version_number)-1
  usable_version_number = build_version_number[:finding_length]
  print("biuld-id:"+ build_id)
  print("biuld-id-version:"+ build_id_version)
  print("usable_version_number:" + usable_version_number)
  return (build_version_number, build_id_version, usable_version_number)

def Build_Time(p3):
  build_time = None
  build_time_idx = p3.find('"build-time":')
  if build_time_idx != -1:
    x = p3[build_time_idx:].find(",")
  build_time = p3[build_time_idx + 13:build_time_idx + x]
  print("build-time:"+ build_time)
  return build_time

def Build_Host(p3):
  build_host_name = None
  build_host_idx = p3.find('"build-hostname":')
  if build_host_idx != -1:
    x = p3[build_host_idx:].find(",")
  build_host_name = p3[build_host_idx + 17:build_host_idx + x]
  build_host_name = build_host_name.replace('"','')
  print("build_host_name:" +  build_host_name)
  print
  return build_host_name

def binary_check():
  p6 =subprocess.run(['file', Production_Binary], stdout=subprocess.PIPE)
  p7 = str(p6)
  p7 =p7.split(",")[9]
  p7 = p7[:-4]
  p7 = p7[1:]
  print("the binary file is:"+ p7)
  return(p7)  

def WhereIsMyDocker(Hostname, BuildVersion, IDVersion):
  global RedHatOs
  build_host_name = Hostname
  build_version_number = BuildVersion
  build_id_version = IDVersion

  if ('centos' in build_host_name ):
    print('we in here')
    RedHatOs = True
  #print(base_path_Vrouter+build_version_number+"."+build_id_version+'-rhel')
  if (RedHatOs):
    docker_path = base_path_Vrouter+build_version_number+"."+build_id_version+'-rhel'
    print(docker_path)
  else:
    docker_path = base_path_Vrouter+build_version_number+"."+build_id_version
  return(docker_path)


def binary_get(BiResult, BuildVersion, IDVersion, USableVersion, PathOfTheDocker ):
  p7 = BiResult
  build_version_number = BuildVersion
  build_id_version = IDVersion
  usable_version_number = USableVersion
  docker_path = PathOfTheDocker

  print("binary get")
  if(p7 == "not stripped"):
   if(build_version_number in containerized_versions):
      print('we out here boysssssss')
      print("fetching binary from the docker...")
      p9  = subprocess.run(['docker', 'ps'], stdout=subprocess.PIPE)
      p10 = subprocess.run(['docker','pull', docker_path], stdout=subprocess.PIPE)
      print(p10.stdout)
      print(docker_path)
      p12 = subprocess.run(['docker','ps','--format','"{{.Names}}"'], stdout=subprocess.PIPE )
      p12 = p12.stdout
      docker_names_list = p12.decode("UTF-8").splitlines()
      for i in range(len(docker_names_list)):
          docker_names_list[i] = docker_names_list[i].replace('"','')
      print("docker-name:"+ docker_names_list[0])
      creating_new_directory_path = subprocess.run(['mkdir','/root/CEM-1289/tf_debugger/'+build_id_version+"_"+build_version_number],stdout=subprocess.PIPE)  
      if (VRouterAgent):
          copier = subprocess.run(['docker','cp',docker_names_list[0] + ":/usr/lib/debug/usr/bin/contrail-vrouter-agent.debug","/root/CEM-1289/tf_debugger/"+build_id_version+"_"+build_version_number+ "/contrail_vrouter_agent."+build_id_version+"_"+build_version_number])
      else:
          copier = subprocess.run(['docker','cp',docker_names_list[0] + ":/usr/lib/debug/usr/bin/contrail-vrouter-agent.debug","/root/CEM-1289/tf_debugger/"+build_id_version+"_"+build_version_number+ "/contrail_vrouter_agent."+build_id_version+"_"+build_version_number])
   else:
      creating_new_directory_path = subprocess.run(['mkdir','/root/CEM-1289/tf_debugger/'+build_id_version+"_"+build_version_number],stdout=subprocess.PIPE)
      print("creating_new_directory_path")
      if (VRouterAgent):
        file_url = URL[0]+usable_version_number+URL[1]+build_id_version+URL[2] 
      else:
        file_url = URL[0]+usable_version_number+URL[1]+build_id_version+URL[3] 
      print(file_url)
      file_object = requests.get(file_url)
      with open('/root/CEM-1289/tf_debugger/'+build_id_version+"_"+build_version_number+'/contrail-vrouter-agent_'+usable_version_number+'_'+build_id_version+"router", 'wb') as local_file:
        local_file.write(file_object.content)
  

def Running_GDB(ID, VERSION, core_file_name, GdbScript):
  build_id_version = ID
  build_version_number = VERSION
  core_file_name = core_file_name
  gdb_script = GdbScript

  running_GDB = subprocess.run(['gdb',"/root/CEM-1289/tf_debugger/"+build_id_version+"_"+build_version_number+ "/contrail_vrouter_agent."+build_id_version+"_"+build_version_number , core_file_name, '-x', gdb_script ])

def Running_GDB(ID, VERSION, core_file_name):
  build_id_version = ID
  build_version_number = VERSION
  core_file_name = core_file_name

  running_GDB = subprocess.run(['gdb',"/root/CEM-1289/tf_debugger/"+build_id_version+"_"+build_version_number+ "/contrail_vrouter_agent."+build_id_version+"_"+build_version_number , core_file_name, '-x', '/root/CEM-1289/tf_debugger/tester_gdb_commands.txt'])


def main():

    if(n==2 and (sys.argv[1]== '-h' or sys.argv[1]== '--help')):
      parser=argparse.ArgumentParser(description='''Here is how to use the TF_Debugger ''',epilog="""TF_DEBUGGER""")
      parser.add_argument('--foo', type=int, default=42, help='FOO!')
      parser.add_argument('bar', nargs='*', default=[1, 2, 3], help='BAR!')
      args=parser.parse_args()

    elif(n == 2):
       print("in condition 2")
       COMMAND_ARGUMENT = sys.argv[1]
       FILE_INFO = core_info(COMMAND_ARGUMENT) # getting p3 Value
       #print('FILE_INFO:' + FILE_INFO )
       FULL_ID = Build_ID(FILE_INFO) #getting ID value
       print("FULL_ID:" + FULL_ID)
       VERSION, ID, USABLE_VERSION = Build_Version(FULL_ID) # getting version and Usable version
       print("VERSION_number:" + VERSION)
       print("VERSION:" + ID)
       print("USABLE_VERSION:" + USABLE_VERSION)
       TIME = Build_Time(FILE_INFO) # getting time
       HOST = Build_Host(FILE_INFO) # getting hostOs
       print("HOST:" + HOST)
       BINARY_RESULT = binary_check() # Getting the result of the bianry
       DOCKER_PATH = WhereIsMyDocker(HOST, VERSION, ID ) # Getting the result of the bianry
       print ('DOCKER_PATH:' +DOCKER_PATH)
       binary_get(BINARY_RESULT, VERSION, ID, USABLE_VERSION, DOCKER_PATH)
       CALLING_GDB = Running_GDB(ID, VERSION, COMMAND_ARGUMENT)

    elif(n==5  and sys.argv[2] == '-debug'):
       global VRouterAgent
       VRouterAgent = False
       COMMAND_ARGUMENT = sys.argv[1]
       FILE_INFO = core_info(COMMAND_ARGUMENT) 
       print('FILE_INFO:' + FILE_INFO )
       FULL_ID = Build_ID(FILE_INFO) 
       print("FULL_ID:" + FULL_ID)
       VERSION, ID, USABLE_VERSION = Build_Version(FULL_ID) 
       print("VERSION_number:" + VERSION)
       print("VERSION:" + ID)
       print("USABLE_VERSION:" + USABLE_VERSION)
       TIME = Build_Time(FILE_INFO) 
       HOST = Build_Host(FILE_INFO) 
       print("HOST:" + HOST)
       BINARY_RESULT = binary_check() 
       DOCKER_PATH = WhereIsMyDocker(HOST, VERSION, ID ) 
       print ('DOCKER_PATH:' +DOCKER_PATH)
       binary_get(BINARY_RESULT, VERSION, ID, USABLE_VERSION, DOCKER_PATH)
       CALLING_GDB = Running_GDB(ID, VERSION, COMMAND_ARGUMENT)

    elif( n == 5 and sys.argv[2] == '-gdb'):
       
       COMMAND_ARGUMENT = sys.argv[1]
       GDBSCRIPT = sys.argv[3]
       FILE_INFO = core_info(COMMAND_ARGUMENT) # getting p3 Value
       print('FILE_INFO:' + FILE_INFO )
       ID = Build_ID(FILE_INFO) #getting ID value
       VERSION, USABLE_VERSION = Build_Version(ID) # getting version and Usable version
       TIME = Build_Time(FILE_INFO) # getting time
       HOST = Build_Host(FILE_INFO) # getting hostOs
       BINARY_RESULT = binary_check() # Getting the result of the bianry
       DOCKER_PATH = WhereIsMyDocker(HOST, VERSION, ID ) # Getting the result of the bianry
       binary_get(BINARY_RESULT, VERSION, ID, USABLE_VERSION, DOCKER_PATH)
       CALLING_GDB = Running_GDB(USABLE_VERSION, VERSION, COMMAND_ARGUMENT, GDBSCRIPT)



    elif(n == 5 and sys.argv[2] == '-f'):
      COMMAND_ARGUMENT = sys.argv[1]
      FILE_INFO = core_info(COMMAND_ARGUMENT)
      ID = Build_ID(FILE_INFO)
      VERSION_BY_USER= sys.argv[3]
      ID_BY_USER = sys.argv[4]
      TIME = Build_Time(FILE_INFO)
      HOST = Build_Host(FILE_INFO)
      BINARY_RESULT = binary_check()
      DOCKER_PATH = WhereIsMyDocker(HOST, VERSION_BY_USER, ID, ID_BY_USER)
      CALLING_GDB = binary_get(BINARY_RESULT, VERSION_BY_USER, ID, ID_BY_USER, DOCKER_PATH)


    else:
      Running_help = subprocess.run(['python3', 'Core_Analyzer.py','-h'])
      sys.exit()


if __name__=="__main__": 
    main()

# till here
#method which will take build_id_version and build_version_number as parameters
'''
  build_version_number = build_V
  build_id_version = build_ID
  usable_version_number = usable_version_number

  if(p7 == "not stripped"):
   if(build_version_number in containerized_versions):
    #if(build_version_number == "2002"):
      print('we out here boysssssss')
      print("fetching binary from the docker...")
      p9  = subprocess.run(['docker', 'ps'], stdout=subprocess.PIPE)
      p10 = subprocess.run(['docker','pull', docker_path], stdout=subprocess.PIPE)
      print(p10.stdout)
    # p10 = subprocess.run(['docker','pull','svl-artifactory.juniper.net/contrail-nightly/contrail-debug:2002.4-rhel'], stdout=subprocess.PIPE)
       print(docker_path)
      p12 = subprocess.run(['docker','ps','--format','"{{.Names}}"'], stdout=subprocess.PIPE )
      p12 = p12.stdout
      docker_names_list = p12.decode("UTF-8").splitlines()
      for i in range(len(docker_names_list)):
          docker_names_list[i] = docker_names_list[i].replace('"','')
      print("docker-name:"+ docker_names_list[0])
      creating_new_directory_path = subprocess.run(['mkdir','/root/CEM-12892/tf_debugger/'+build_id_version+"_"+build_version_number],stdout=subprocess.PIPE)  
      copier = subprocess.run(['docker','cp',docker_names_list[0] + ":/usr/lib/debug/usr/bin/contrail-vrouter-agent.debug","/root/CEM-12892/tf_debugger/"+build_id_version+"_"+build_version_number+ "/contrail_vrouter_agent."+build_id_version+"_"+build_version_number])

   else:
      file_url = 'http://10.84.5.100/cs-shared/github-build/R'+usable_version_number+"x/"+build_id_version+"/redhat70/newton/sandbox/build/debug/vnsw/agent/contrail/contrail-vrouter-agent" 
      print(file_url)
      file_object = requests.get(file_url)
      with open('/root/CEM-12892/tf_debugger/debugger_files/contrail-vrouter-agent_'+usable_version_number+'_'+build_id_version, 'wb') as local_file:
        local_file.write(file_object.content)


 # running GDB method (build_version_number, build_version_number)
    running_GDB = subprocess.run(['gdb',"/root/CEM-12892/tf_debugger/"+build_id_version+"_"+build_version_number+ "/contrail_vrouter_agent."+build_id_version+"_"+build_version_number , core_file_name, '-x', '/root/CEM-12892/tf_debugger/tester_gdb_commands.txt'])

  else:
    running_GDB = subprocess.run(['gdb',"/root/CEM-12892/tf_debugger/"+build_id_version+"_"+build_version_number+ "/contrail_vrouter_agent."+build_id_version+"_"+build_version_number , core_file_name, '-x', '/root/CEM-12892/tf_debugger/tester_gdb_commands.txt'])
'''
