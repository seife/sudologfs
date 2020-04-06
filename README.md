# sudologfs
A filesystem to ship sudo logs to remote syslog servers

## Purpose
sudo allows to log terminal output via the "log_output" directive. This is a useful feature for auditing purposes (who did what when?).
Unfortunately, once a user has become root via sudo, he can easily tamper the logs sudo is writing. In order to make these logs safe against tampering, sudologfs sends them to a remote host immediately upon writing.

## Technical details
sudologfs simply passes through all file system operations to the underlying file system. It only hooks into the "write" function, sending all data that is passed to write to the remote host, after writing them to the local file system.
The transport mechanism to the remote server is "syslog via UDP", for simplicity. In the future, different transfer methods might be implemented.
Since syslog cannot reliably transport / store arbitrary binary data (and terminal output does contain binary data), the write buffer is encoded with BASE64 method before transferring it.
The syslog packet looks like this:

    SYSLOG_HEADER ABSOLUTE_FILENAME:SEQUENCE_NUMBER length@offset BASE64_ENCODED_BUFFER
Note that the syslog RFC only allows 1024 byte long packets (and UDP transport should stay below the MTU anyway), so more than one packet might need to be sent to transer "length" BASE64 encoded bytes.
Only the first of these sequential packets contains the "length@offset" header, which will be used when extracting the files from the receiving syslog.
The sequence number is increased with each transmitted packet to allow reconstruction of the files and detection of lost packets on the receiving side.

## Usage
Build with standard "./configure;make;sudo make install", when building from git use ./autogen.sh before.  
Mount the file system:

    sudologfs /var/log/sudo-backing /var/log/sudo-io my-loghost.mydomain.tld[:port]

On the receiving machine ("my-loghost.mydomain.tld"), the syslog needs to be configured to receive sudologfs' UDP messages, and (optionally) filter them out to a separate file.  
Example for rsyslogd, put this into /etc/rsyslog.d/sudologfs-receiver.conf

    $ModLoad imudp.so         # provides UDP syslog reception
    $UDPServerRun 514         # start a UDP syslog server at standard port 514
    $template SudologFile, "/var/log/sudolog/%HOSTNAME%/sudologfs.log
    if $syslogfacility == 13 then {
        ?SudologFile
    }

## Example fstab

    /var/log/sudo-backing /var/log/sudo-io  fusefs.sudologfs   rw,mountprog=/usr/local/bin/sudologfs,syslog=192.0.2.10:514

## Limitations
  * Long file names will not work (the filename/sequence number prefix will use all the space in the syslog packet)  
    This is a deliberate design decision in order to allow easy extraction of the data from the receiving log server.
    It does not interfere with the intended use of this file system for sudo log shipping, because file names are short in this case.
  * UDP transport is unreliable  
    Yes. But easy to implement and it does not fail. See RFC 1925 §7a

## Credits
Initial code was borrowed from Joseph J. Pfeiffer, Jr.'s excellent tutorial "How to write a FUSE File System" at http://www.cs.nmsu.edu/~pfeiffer/fuse-tutorial.  
The BASE64 implementation (cencode.h, cencode.c) is copied from libb64 project: http://sourceforge.net/projects/libb64.
