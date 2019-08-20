FROM ubuntu:18.04

RUN apt-get update
RUN apt-get install -y xinetd git wget python automake libtool make gcc netcat build-essential
 
RUN sysctl -w kernel.dmesg_restrict=1 
RUN chmod 1733 /tmp /var/tmp /dev/shm
RUN adduser ytf

ADD ./wrapper.py /home/ytf/wrapper.py
ADD ./build_yara.sh /home/ytf/build_yara.sh
ADD ./patchfile /home/ytf/patchfile
ADD ./flag /home/ytf/flag
ADD ./rule /home/ytf/rule
ADD ./xinetd_config /etc/xinetd.d/challenge

RUN chown -R root:root /home/ytf
RUN chown root:ytf /home/ytf/wrapper.py
RUN chmod 2755 /home/ytf/wrapper.py
RUN chown root:ytf /home/ytf/flag
RUN chmod 440 /home/ytf/flag
RUN chown root:ytf /home/ytf/build_yara.sh
RUN chmod 1755 /home/ytf/build_yara.sh
RUN chown root:ytf /home/ytf/rule
RUN chmod 1744 /home/ytf/rule
RUN /home/ytf/build_yara.sh
RUN chown root:ytf /usr/local/bin/yara
RUN chmod 2755 /usr/local/bin/yara

RUN service xinetd restart
CMD ["/usr/sbin/xinetd", "-dontfork"]
