data = {
    'CyberSecLabs - Brute': {
        'Link': 'https://youtu.be/dO3UwMbV6-A',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:50 HackTricks Active Directory AD methodology\n\
01:10 Enumerating users with nmap kerberos script, picking usernames list from SecLists\n\
03:30 ASREPRoasting the usernames we enumerated (with GetNPUsers from impacket)\n\
05:20 Bruteforcing Tess hash with John\n\
05:50 WinRM login with evil-winrm\n\
07:20 DNSAdmins group privesc without crashing the DNS service by creating our own dll and setting it as the serverlevelplug and restarting the server sc\n\
11:40 Explaining real life scenario without permissions to start dns service\n\
12:40 We didn\'t crash the dns service. Explaining why that\'s great!'
    },
    'CyberSecLabs - Fuel': {
        'Link': 'https://youtu.be/cAVaHenL7s8',
        'Timestamps': '00:00 Introduction\n\
00:15 Nmap scan\n\
00:30 Fuel CMS, version 1.4 - Exploit\n\
01:20 Looking into the Fuel CMS RCE exploit\n\
01:40 URL decoding with CyberChef\n\
02:00 Running the RCE, fixing errors\n\
03:30 Getting RCE, finding the private RSA key to get SSH access\n\
05:20 Checking the .bash_history file to find a plaintext password\n\
06:00 Using the password to su to root'
    },
    'CyberSecLabs - Toast': {
        'Link': 'https://youtu.be/CndMDvjX8dg',
        'Timestamps': '00:00 Introduction\n\
00:15 nmap scan\n\
00:35 Enumerating SMB with crackmapexec\n\
01:00 Finding usernames\n\
02:20 ASREPRoasting users with GetNPUsers and cracking the resulting hash\n\
05:40 Manually enumerating LDAP in python\n\
09:00 Checking smb share with new credenials\n\
10:00 Getting RCE but there is some AV and AMSI\n\
12:50 Bypassing AMSI by obfscating with ISESteroids\n\
15:30 Getting first reverse shell, it\'s unstable, we upgrade using nc.exe over a smb share\n\
17:30 Setting up our SMB server\n\
18:50 Running WinPEAS on the box\n\
21:00 Exploiting unquoted service path\n\
22:30 Turning ps1 script into exe for exploiting unquoted service path\n\
25:00 Making shell more stable\n\
27:00 Checking powershell history\n\
28:00 Spraying new password on smb and winrm with crackmapexec\n\
29:30 We have debug and impersonate privilege\n\
30:00 Building sharpsploit and loading the dll into our session with evil-winrm Dll-Loader\n\
33:00 Dumping SAM with SharpSploit.dll\n\
34:00 Logging in with the admin hash'
    },
    'CyberSecLabs - Pie': {
        'Link': 'https://youtu.be/2u0PbBVFIPc',
        'Timestamps': '00:00 Introduction\n\
00:10 Checking port 80\n\
00:20 Explaining pi-hole\n\
00:50 Pi-Hole admin panel access\n\
01:05 Searchsploit for pi-hole exploits\n\
02:00 Checking the pi-hole RCE exploit and running it'
    },
    'CyberSecLabs - Casino': {
        'Link': 'https://youtu.be/ZwYqDZOvUpY',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:30 Enumeration of port 80\n\
01:20 Running Gobuster\n\
02:20 Trying SSTI Server side template injection\n\
04:00 Using XSS to grab admin cookie\n\
06:30 Casino access\n\
07:00 Exploiting SSRF to get access to an internally open port\n\
09:00 Using RCE to get a ssh session on the box\n\
12:40 Finding git repository with credentials\n\
13:50 Using pythonpath to load and execute vulnerable module running as root'
    },
    'CyberSecLabs - Eternal': {
        'Link': 'https://youtu.be/tlB6cyTo8Yw',
        'Timestamps': '00:00 Introduction\n\
00:10 EternalBlue'
    },
    'CyberSecLabs - Shock': {
        'Link': 'https://youtu.be/AWyS60GMZzs',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:40 Running gobuster to search for directories\n\
01:20 We find cgi-bin folder, scanning that\n\
02:10 Searching for apache cgi exploits, finding shellshock\n\
02:50 Exploiting apache shellshock in metasploit\n\
04:20 Explaining shellshock\n\
06:40 Uploading and running linpeas using meterpreter\n\
07:30 Sudo -l shows we can execute socat as root'
    },
    'CyberSecLabs - Weak': {
        'Link': 'https://youtu.be/bVd_Z321Tw0',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap\n\
00:40 Using files to connect to ftp anonymously\n\
01:30 Checking if the webroot is actually the ftp share\n\
02:30 Explain wappalyzer\n\
03:00 Trying to upload php, it fails\n\
04:00 Using an aspx web shell (SharPyShell)\n\
05:40 Enumerating the Development directory, seeing credentials\n\
06:40 Using crackmapexec to test password on users\n\
07:20 Good login (PWNED) Using psexec.py to get RCE'
    },
    'CyberSecLabs - Red': {
        'Link': 'https://youtu.be/XonqZUaqioM',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:30 Checking out redis\n\
01:00 Checking redis RCE with searchsploit\n\
01:30 Explaing the redis RCE\n\
04:40 Executing the RCE\n\
05:20 Loaded the evil module in redis, getting reverse shell\n\
09:00 Running pspy to see if root runs any processes\n\
11:00 Checking the log-manager.sh file, which executes files\n\
12:00 Creating a shell file to get a reverse shell as root'
    },
    'CyberSecLabs - Monitor': {
        'Link': 'https://youtu.be/mq8zNhUH7Jw',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:30 Checking out port 80, where we try default credentials on PRTG network manager\n\
01:00 Checking smb without credentials using smbclient.py\n\
01:30 Getting the dev files from the WebBackups share and checking that out\n\
02:15 Opening the database in sqlite3 and getting credentials that work on PRTG\n\
03:00 Checking RCE exploits on PRTG using searchsploit\n\
03:30 Reading the RCE and changing the code because adding a user is too noisy\n\
05:00 Using rundll32 to get a reverse shell with metasploit as system'
    },
    'CyberSecLabs - Lazy': {
        'Link': 'https://youtu.be/SqpWNgsR1TM',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:20 Checking samba version for exploits with searchsploit\n\
00:40 Reading up on is_known_pipename() exploit\n\
01:30 Checking if we can use samba without credentials\n\
02:30 Running the is_known_pipename exploit in metasploit'
    },
    'CyberSecLabs - Stack': {
        'Link': 'https://youtu.be/5GB080t8OU8',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:30 Checking out port 80, it runs a debug django instance\n\
01:05 Logging into gitstack with default credentials\n\
01:30 Finding an RCE exploit for gitstack and running it\n\
04:00 Using regsvr32 in metasploit to get a reverse shell\n\
06:00 Running winpeas on the box\n\
08:00 We get a keepass password database, which we crack with john\n\
10:00 Trying to login with evil-winrm, fails\n\
11:00 Search Invoke-Command on hacktricks but we need a powershell session\n\
12:20 Getting a powershell shell\n\
12:30 Running Invoke-Command\n\
14:10 Using nc.exe to get a reverse shell as administrator'
    },
    'CyberSecLabs - Deployable': {
        'Link': 'https://youtu.be/3YWOggMiKu4',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:30 Checking out apache tomcat on port 8080\n\
01:10 Checking login for manager page on tomcat, they use default credentials\n\
01:45 Manually creating a jsp file to deploy in tomcat, to give us a webshell\n\
03:45 Code exec, we get a reverse meterpreter shell with regsvr32\n\
05:50 Uploading and running winpeas with meterpreter\n\
07:10 We have a service with a path without quotes and spaces, and a directory we can change\n\
08:50 We can check the configuration of the service\n\
10:20 Creating our reverse tcp shell with msfvenom\n\
11:15 Uploading shell to service.exe and starting service'
    },
    'CyberSecLabs - Leakage': {
        'Link': 'https://youtu.be/WeHYVYRjeg8',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:23 Checkin out gitlab on port 80, making an account\n\
00:50 Checking out public projects on gitlab seeing a commit to config.php containing credentials\n\
01:35 Testing credentials on gitlab\n\
01:45 Access to a new project containing a private rsa key, which we use to ssh in as jonathan\n\
02:30 Key has a password so let\'s crack the key with john and ssh2john\n\
03:20 Uploading linpeas with scp\n\
04:00 Running linpeas.sh\n\
05:10 nano has SUID bit set, we can run it as root\n\
06:00 Uploading public key to /root/.ssh/authorized_keys to ssh as root'
    },
    'CyberSecLabs - Engine': {
        'Link': 'https://youtu.be/wpiA3wMawfw',
        'Timestamps': '00:00 Introduction\n\
00:10 NMap scan\n\
00:40 Gobuster on webroot\n\
01:15 Gobuster found blog page\n\
02:30 Logging into admin page with admin:admin\n\
02:50 Checking blogengine version to look for exploits\n\
03:30 Testing RCE vulnerability on blogengine\n\
06:00 Uploading nc so we have a slightly better shell with certutil\n\
09:30 Uploading and running winpeas\n\
10:50 Using autologon credentials to login with evil-winrm'
    },
    'CyberSecLabs - Sam': {
        'Link': 'https://youtu.be/68762UPEtho',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan explanation\n\
00:40 Checking credential-less smb login\n\
01:23 Mounting the backups share\n\
02:30 Enumeration the filesystem we mounted\n\
03:20 Checking the SAM file on the filesystem\n\
04:40 Running impacket\'s secretsdump with our SAM and SYSTEM file, giving us hashes\n\
05:15 Checking evil-winrm access as jamie with hash\n\
06:15 Checking the services\n\
07:22 Services cheatsheet\n\
07:32 Can we modify this service with sc config?\n\
08:15 Can we modify the binary that the service is executing?\n\
08:50 Can we modify the binaries with icacls?\n\
09:40 Can we start and stop the service? Checking service permissions with sc sdshow\n\
11:15 Creating the exe reverse shell using msfvenom\n\
12:45 Starting the service and getting a shell back'
    },
    'CyberSecLabs - Unroot': {
        'Link': 'https://youtu.be/3OU5y-qrWnw',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:40 Gobuster scanning the webroot for files\n\
01:45 Finding the dev directory\n\
02:00 Command injection from ping to reverse php shell\n\
04:55 Running sudo -l, we notice !root and check if our version is vulnerable to CVE-2019-14287\n\
06:30 Explaining CVE-2019-14287 (sudo -l !root, below 1.8.28)'
    },
    'CyberSecLabs - Imposter': {
        'Link': 'https://youtu.be/cU6-l6AGF3Q',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan explaining all ports\n\
00:20 Explaining RPC\n\
01:00 Explaining RDP\n\
01:25 Explain port 5985\n\
01:35 Port 8080 is interesting\n\
02:00 We try easy credentials (admin, password, ..) and get credentials\n\
03:00 Looking at WingFTP\n\
03:25 We have code execution in the lua console\n\
03:55 Using regsvr32 to get a shell on the box using metasploit\n\
06:15 Using burp since we can\'t paste in the console\n\
07:50 Meterpreter reverse shell returned\n\
08:05 Enumeration with whoami /priv to see the token privileges\n\
08:50 Loading incognito in meterpreter\n\
09:15 Listing token that we can impersonate\n\
10:00 Impersonating NT AUTHORITY\SYSTEM token with incognito'
    },
    'CyberSecLabs - Secret': {
        'Link': 'https://youtu.be/i4bc0N0dMx4',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:20 Checking anonymous / guest login on smb using smbclient.py\n\
01:12 Mounting smb share locally using mount\n\
02:45 Reading default password\n\
03:00 Formatting usernames using ctf-wordlist-names in active directory style\n\
04:20 Bruteforcing usernames for our found password with crackmapexec\n\
05:08 Finding valid credentials and logging in using evil-winrm\n\
06:15 Uploading file in evil-winrm\n\
06:25 Explaining what SharpHound is and how Bloodhound works (with neo4j)\n\
08:10 We can\'t find anything of interest in bloodhound so we run winpeas.exe\n\
10:00 Finding autologon credentials and trying them on the users we have\n\
10:45 New credentials found. Checking bloodhound if we can do anything as this user\n\
11:30 From local administrator to domain admin using genericWrite and net group "domain admins" user /add /domain\n\
12:15 Using mimikatz and lsadump::lsa /patch to get the hash for administrator\n\
13:30 Logging in to evil-winrm with an NTLM hash'
    },
    'CyberSecLabs - Potato': {
        'Link': 'https://youtu.be/xUHFQsncsyc',
        'Timestamps': '00:00 Introduction\n\
00:08 Nmap scan\n\
00:15 Looking at port 8080, running Jenkins\n\
00:27 Admin admin credentials work on the Jenkins website\n\
00:45 Checking hacktricks for Jenkins code exec\n\
01:05 Getting code exec in jenkins through the groovy script console\n\
01:45 Running a powershell reverse shell using iwr\n\
02:41 Using a nishang oneliner shell: https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1\n\
04:40 Upgrading shell to meterpreter\n\
05:56 SeImpersonatePrivilege escalation through JuicyPotato'
    },
    'CyberSecLabs - CMS': {
      'Link': 'https://youtu.be/nnlfJbFKt2Y',
        'Timestamps': '00:00 Introduction\n\
00:15 Running nmap\n\
00:33 Checking out the webpage at port 80 and seeing that it\'s running wordpress\n\
00:55 Running wpscan to see if there\'s any vulnerable wordpress plugins, We use searchsploit and find an exploit that we decide to run\n\
02:30 We now have local file inclusion on the box and check out the methodology in HackTricks, which shows us how we can use /proc/self/status to get the current user and then including /home/angel/.ssh/id_rsa to get the private key\n\
04:54 Giving the private key proper permissions in order to be able to use it to log in using ssh\n\
05:30 Running sudo -l to see that we can run any command as sudo and using that to get a root shell'
    },
    'CyberSecLabs - Debug': {
        'Link': 'https://youtu.be/J8v2QQ9ILto',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:20 Gobuster on webroot\n\
00:40 Manually checking webpag\ne\
01:18 Gobuster find console page\n\
01:30 We find a flask interactive console and use it to get a reverse shell\n\
01:55 Our flask shell isn\'t working reliably, seems like sometimes we get a 404\n\
02:13 Checking out Pentestmonkeys\n\
02:30 Using rlwrap to make our live easier once the shell returns\n\
03:22 Running linpeas to enumerate\n\
05:00 Checking gtfobins for a suid binary we can run as root\n\
05:55 Reading /etc/shadow and cracking the hashes with john\n\
06:47 Hash cracked, can we su as root with this password?'
    },
    'CyberSecLabs - Cold': {
        'Link': 'https://youtu.be/D0lI12DUg7Y',
        'Timestamps': '00:00 Introduction\n\
00:10 Nmap scan\n\
00:33 Checking out port 80, finding phpinfo open\n\
01:10 Finding something around coldfusion and deciding to check that out\n\
01:30 Checking out blogpost about pentesting coldfusion, mentioning a directory\n\
02:00 Looking for a coldfusion file somewhere, eventually finding the admin login\n\
03:45 Looking for exploits for coldfusion\n\
04:05 Using metasploit to exploit a vulnerability in coldfusion\n\
05:16 Upgrading shell to meterpreter with msfvenom and exploit/multi/handler\n\
11:00 Running winPEAS on the box\n\
12:40 Finding that we can modify a service\'s binpath to get a shell as system\n\
15:25 Our shell is unstable so we create another user, add him to administrators, so we can evil-winrm in as the new user'
    },
    'CyberSecLabs - Office': {
    'Link': 'https://youtu.be/PcV3tOw7f_k',
    'Timestamps': '00:00 Introduction\n\
00:15 Running nmap\n\
00:30 Running gobuster dir scans on http and https\n\
01:17 Adding a found hostname to /etc/hosts\n\
02:45 Checking out a forum page on https and notice a possible LFI page\n\
03:40 Using wfuzz to automatically fuzz the LFI\n\
06:00 From LFI we get a hash for dwight, that we crack with john\n\
06:40 Testing the password on ssh and wordpress, the latter works\n\
07:40 Using wordpress to upload a php file that we can use for a python reverse shell from pentestmonkeys\n\
09:40 Upgrading shell to tty and showcasing ctf-bash-tools on github\n\
10:00 Running sudo -l to get access to dwight\n\
11:09 Running linpeas to enumerate the box\n\
12:35 Finding a filtered port that is locally open, using ssh to port forward this port\n\
14:40 We exploit webmin on port 10000 with metasploit exploit/linux/http/webmin_backdoor'
},
    'CyberSecLabs - Shares': {
        'Link': 'https://youtu.be/XYu6okeIaog',
        'Timestamps': "00:00 Introduction\n\
00:15 Running nmap\n\
00:50 Enumeration nfs\n\
01:12 Mounting an nfs share to a local dir\n\
01:45 Finding a private ssh key in the share, we use that to log in using ssh\n\
03:18 Cracking the private key using john and ssh2john to get the password\n\
04:32 Running sudo -l to see that we can use python and gtfobins to get a shell as amy\n\
06:20 Running sudo -l to see that we can execute ssh as root and using gtfobins to find a way to exploit that"
    },
    'CyberSecLabs - Roast': {
        'Link': 'https://youtu.be/_VG1g_XRw4U',
        'Timestamps': '00:00 Introduction\n' +
            '00:18 HackTricks - Collection of cheatsheets\n' +
            '00:40 Enumerating ldap with nmap command and finding user with password in the description\n' +
            '01:20 Running crackmapexec to test found password on found usernames, finding valid credentials\n' +
            '04:00 Running evil-winrm for crhodes with password\n' +
            '04:52 Uploading and running SharpHound to the box to ingest data from the domain controller\n' +
            '06:14 Processing data in BloodHound. We find that there is a path to domain admin from a kerberoastable user roastsvc via GenericWrite\n' +
            '07:30 Kerberoasting users using GetUserSPNs from impacket\n' +
            '08:30 Cracking hash from kerberoasted user roastsvc\n' +
            '09:30 Using cracked password to log in using evil-winrm on roastsvc\n' +
            '09:50 Exploiting generic write on Domain admin by adding ourselves to the domain admins group\n' +
            '10:20 Uploading and running mimikatz in order to dump the administrator hash using lsadump\n' +
            '11:30 Logging in with administrator NTLM hash using evil-winrm'
    },
    'CyberSecLabs - Boats': {
        'Link': 'https://youtu.be/TwmHAzu0AeY',
        'Timestamps': '00:00 Introduction\n' +
                '00:12 Running nmap on the windows box\n' +
                '00:30 Running gobuster on port 80\n' +
                '01:00 Doing manual enumeration on port 80 whilst waiting for our automatic recon to finish\n' +
                '01:45 Looking at the output from gobuster and checking the phpmyadmin file\n' +
                '02:07 Checking out the open phpmyadmin portal\n' +
                '02:35 Using phpmyadmin to get a shell on the box through uploading php code with a sql query\n' +
                '03:40 Checking out hacktricks to look for a good reverse shell in windows, we decide to user certutil\n' +
                '04:40 Using msfvenom to create a reverse meterpreter binary\n' +
                '05:35 Uploading our binary with certutil and running it\n' +
                '06:55 Using metasploit to catch our reverse meterpreter shell with exploit/multi/handler'
    },
    'CyberSecLabs - Outdated': {
        'Link': 'https://youtu.be/hjs-2X3CjAU',
        'Timestamps': '00:00 Introduction\n' +
               '00:15 Nmap scan\n' +
               '00:39 Checking nfs shares with showmount\n' +
               '01:00 Mounting the remote nfs share\n' +
               '01:57 Searching for ProFTP exploits\n' +
               '02:18 Explaining why the metasploit exploit won\'t work in this case\n' +
               '03:00 Checking out some exploit code for ProFTP to see if we can make it work for out specific case\n' +
               '03:40 Exploiting mod_copy for ProFTP\n' +
               '05:35 Reading daniels home folder, getting the private key\n' +
               '06:10 SSHing with private key (with correct permissions)\n' +
               '07:00 Uploading files with scp\n' +
               '07:40 Running linpeas.sh\n' +
               '07:50 Seeing a possible kernel exploit so we check https://github.com/lucyoa/kernel-exploits\n' +
               '08:20 Reading up on the overlayfs kernel exploit\n' +
               '09:35 Running the overlayfs exploit binary and getting root'
    }
}

function searchword(word) {
    result = {}
    for (let video in data) {
        text = data[video]['Timestamps'];
        for (let timestamp of text.split('\n')) {
            if (timestamp.toLowerCase().includes(word.toLowerCase())) {
                result[video + ' ' + timestamp.substring(0, 5)] = timestamp.substring(6);
            }
        }
    }
    return result;
}


function showdata(toshow) {
    let table = document.getElementById('result').lastChild
    for (let video in toshow) {
        let tr = document.createElement('tr');

        let td_link = document.createElement('td');
        td_link.setAttribute('class', 'col-1')
        let a = document.createElement('a');
        let time = video.substring(video.length - 5).split(':');
        a.setAttribute('href', data[video.substring(0, video.length - 6)]['Link'] + '?t=' + (parseInt(time[0]) * 60 + parseInt(time[1])).toString());
        a.textContent = video.substring(0, video.length - 6);
        td_link.appendChild(a);
        tr.appendChild(td_link);

        let td_timestamp = document.createElement('td');
        td_timestamp.setAttribute('class', 'col-2')
        td_timestamp.textContent = video.substring(video.length - 5);
        tr.appendChild(td_timestamp);

        let td_text = document.createElement('td');
        td_text.setAttribute('class', 'col-3')
        td_text.textContent = toshow[video];
        tr.appendChild(td_text);

        table.appendChild(tr);
    }
}

function cleardata() {
    let table = document.getElementById('result').lastChild
    while (table.firstChild !== table.lastChild) {
        table.removeChild(table.lastChild);
    }
}

function onfocus() {
    let element = document.getElementById("cover");
    element.style.width = "80%";
}

function onfocusout() {
    let element = document.getElementById("cover");
    element.style.width = "20%";
}

window.onload = function() {
    Particles.init({
        selector: '.background',
        connectParticles: true
    });
};

function onclick() {
    let search = document.getElementById('search')
    if (search.value.length > 2) {
       cleardata();
        showdata(searchword(search.value));
    }
}

let element = document.getElementById("cover");
element.addEventListener("focusin", onfocus);
element.addEventListener("focusout", onfocusout);

let searchbutton = document.getElementById('searchButton');
searchbutton.addEventListener('click', onclick);
document.getElementById('search').addEventListener('input', onclick);

// showdata(data);
