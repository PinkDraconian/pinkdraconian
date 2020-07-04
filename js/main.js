data = {
    'CyberSecLabs - CMS': {
      'Link': 'https://youtu.be/nnlfJbFKt2Y',
        'Timestamps': '00:00 Introduction\
00:15 Running nmap\
00:33 Checking out the webpage at port 80 and seeing that it\'s running wordpress\
00:55 Running wpscan to see if there\'s any vulnerable wordpress plugins, We use searchsploit and find an exploit that we decide to run\
02:30 We now have local file inclusion on the box and check out the methodology in HackTricks, which shows us how we can use /proc/self/status to get the current user and then including /home/angel/.ssh/id_rsa to get the private key\
04:54 Giving the private key proper permissions in order to be able to use it to log in using ssh\
05:30 Running sudo -l to see that we can run any command as sudo and using that to get a root shell'
    },
    'CyberSecLabs - Debug': {
        'Link': 'https://youtu.be/J8v2QQ9ILto',
        'Timestamps': '00:00 Introduction\
00:10 Nmap scan\
00:20 Gobuster on webroot\
00:40 Manually checking webpage\
01:18 Gobuster find console page\
01:30 We find a flask interactive console and use it to get a reverse shell\
01:55 Our flask shell isn\'t working reliably, seems like sometimes we get a 404\
02:13 Checking out Pentestmonkeys\
02:30 Using rlwrap to make our live easier once the shell returns\
03:22 Running linpeas to enumerate\
05:00 Checking gtfobins for a suid binary we can run as root\
05:55 Reading /etc/shadow and cracking the hashes with john\
06:47 Hash cracked, can we su as root with this password?'
    },
    'CyberSecLabs - Cold': {
        'Link': 'https://youtu.be/D0lI12DUg7Y',
        'Timestamps': '00:00 Introduction\
00:10 Nmap scan\
00:33 Checking out port 80, finding phpinfo open\
01:10 Finding something around coldfusion and deciding to check that out\
01:30 Checking out blogpost about pentesting coldfusion, mentioning a directory\
02:00 Looking for a coldfusion file somewhere, eventually finding the admin login\
03:45 Looking for exploits for coldfusion\
04:05 Using metasploit to exploit a vulnerability in coldfusion\
05:16 Upgrading shell to meterpreter with msfvenom and exploit/multi/handler\
11:00 Running winPEAS on the box\
12:40 Finding that we can modify a service\'s binpath to get a shell as system\
15:25 Our shell is unstable so we create another user, add him to administrators, so we can evil-winrm in as the new user'
    },
    'CyberSecLabs - Office': {
    'Link': 'https://youtu.be/PcV3tOw7f_k',
    'Timestamps': '00:00 Introduction\
00:15 Running nmap\
00:30 Running gobuster dir scans on http and https\
01:17 Adding a found hostname to /etc/hosts\
02:45 Checking out a forum page on https and notice a possible LFI page\
03:40 Using wfuzz to automatically fuzz the LFI\
06:00 From LFI we get a hash for dwight, that we crack with john\
06:40 Testing the password on ssh and wordpress, the latter works\
07:40 Using wordpress to upload a php file that we can use for a python reverse shell from pentestmonkeys\
09:40 Upgrading shell to tty and showcasing ctf-bash-tools on github\
10:00 Running sudo -l to get access to dwight\
11:09 Running linpeas to enumerate the box\
12:35 Finding a filtered port that is locally open, using ssh to port forward this port\
14:40 We exploit webmin on port 10000 with metasploit exploit/linux/http/webmin_backdoor'
},
    'CyberSecLabs - Shares': {
        'Link': 'https://youtu.be/XYu6okeIaog',
        'Timestamps': "00:00 Introduction\
00:15 Running nmap\
00:50 Enumeration nfs\
01:12 Mounting an nfs share to a local dir\
01:45 Finding a private ssh key in the share, we use that to log in using ssh\
03:18 Cracking the private key using john and ssh2john to get the password\
04:32 Running sudo -l to see that we can use python and gtfobins to get a shell as amy\
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
